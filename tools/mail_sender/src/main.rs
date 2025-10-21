#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
// We allow expect since it forces good error messages at the least.
#![allow(clippy::expect_used)]

use crate::config::Config;
use chrono::Utc;
use clap::Parser;
use cron::Schedule;
use hashbrown::HashSet;
use kanidm_client::KanidmClient;
use kanidm_client::KanidmClientBuilder;
use kanidm_lib_file_permissions::readonly as file_permissions_readonly;
use kanidm_proto::v1::OutboundMessage;
use kanidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
use lettre::{
    address::Address, message::header::ContentType, message::Mailbox,
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use std::fs::metadata;
use std::fs::File;
use std::io::Read;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tokio::runtime;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

mod config;
include!("./opt.rs");

const CHANNEL_CAPACITY: usize = 16;

#[derive(Debug)]
enum SendError {
    InvalidDestinationAddress,
    MessageBuild,
    Transport,
}

struct QueuedMessage {
    message_id: Uuid,
    to_address: String,
    ob_msg_template: OutboundMessage,
}

struct MessageStatus {
    message_id: Uuid,
    status: Result<(), SendError>,
}

fn to_email_content(msg: &OutboundMessage, message_id: Uuid) -> (String, String) {
    match msg {
        OutboundMessage::TestMessageV1 { display_name } => (
            "Kanidm Test Message".into(),
            format!(
                r#"Hi {display_name},

This is a test message sent by Kanidm to ensure that we are able to email you.

msg_id: {message_id}
            "#
            ),
        ),
    }
}

async fn send_message(
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    destination: String,
    ob_msg_template: OutboundMessage,
    message_id: Uuid,
    config: &Config,
) -> Result<(), SendError> {
    let to_addr = destination.parse::<Address>().map_err(|err| {
        error!(?err, "invalid destination address");
        SendError::InvalidDestinationAddress
    })?;
    let to = Mailbox::new(None, to_addr.clone());

    let from = Mailbox::new(
        Some(config.mail_from_display_name.clone()),
        config.mail_from_address.clone(),
    );

    let reply_to = Mailbox::new(
        Some(config.mail_from_display_name.clone()),
        config.mail_reply_to_address.clone(),
    );

    let (subject, body) = to_email_content(&ob_msg_template, message_id);

    let email = Message::builder()
        .from(from)
        .reply_to(reply_to)
        .to(to)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|err| {
            error!(?err, "unable to build message");
            SendError::MessageBuild
        })?;

    match mailer.send(email).await {
        Ok(_) => {
            info!("Email sent successfully!");
            Ok(())
        }
        Err(err) => {
            error!(?err, "Unable to send message");
            Err(SendError::Transport)
        }
    }
}

async fn mail_driver(
    mut broadcast_rx: broadcast::Receiver<()>,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    config: &Config,
    mut outbound_rx: mpsc::Receiver<QueuedMessage>,
    response_tx: mpsc::Sender<MessageStatus>,
) {
    loop {
        tokio::select! {
            biased;
            _ = broadcast_rx.recv() => {
                // stop the event loop!
                break;
            }
            Some(QueuedMessage {
                message_id, to_address, ob_msg_template
            }) = outbound_rx.recv() => {
                // FUTURE: If this becomes a bottleneck, we could spawn each message as a task.

                // Dequeue the message
                let status = send_message(
                    mailer,
                    to_address,
                    ob_msg_template,
                    message_id,
                    config,
                ).await;

                let msg_status = MessageStatus {
                    message_id,
                    status
                };

                // Send a response about the result.
                if let Err(reason) = response_tx.send(msg_status).await {
                    warn!(?reason, "Unable to queue message status");
                }
            }
        }
    }
}

async fn mail_checker(
    mut broadcast_rx: broadcast::Receiver<()>,
    outbound_tx: mpsc::Sender<QueuedMessage>,
    mut response_rx: mpsc::Receiver<MessageStatus>,
    schedule: Schedule,
    rsclient: KanidmClient,
) {
    let mut message_seen: HashSet<Uuid> = HashSet::new();

    'outer: loop {
        let now = Utc::now();
        let next_time = match schedule.after(&now).next() {
            Some(v) => v,
            None => {
                error!("Failed to access any future scheduled events, terminating.");
                break;
            }
        };

        // If we don't do 1 + here we can trigger the event multiple times
        // rapidly since we are in the same second.
        let wait_seconds = 1 + (next_time - now).num_seconds() as u64;
        info!(
            "next mail check on {}, wait_time = {}s",
            next_time, wait_seconds
        );

        tokio::select! {
            biased;
            // First, ack anything that was sent.
            Some(MessageStatus {
                message_id, status
            }) = response_rx.recv() => {
                // Mark that we are no longer processing this message id.
                let _ = message_seen.remove(&message_id);
                // process the response, normally by marking it as done in Kanidm.
                if status.is_ok() {
                    if let Err(client_error) = rsclient.idm_message_mark_sent(message_id).await {
                        error!(?client_error, ?message_id, "Unable to mark message as sent.")
                    }
                }
            }
            // Now check if we are shutting down?
            _ = broadcast_rx.recv() => {
                // stop the event loop!
                break;
            }
            // Check for new mail, and queue it if needed.
            _ = sleep(Duration::from_secs(wait_seconds)) => {
                info!("checking for mail ...");
                match rsclient.idm_message_list_ready().await {
                    Ok(message_list) => {
                        for message in message_list.resources {
                            if !message_seen.insert(message.header.id) {
                                // Message already seen and queued, skip.
                                continue;
                            }

                            // In theory, by iterating *here* what this means is that
                            // we are going to mark the message as successfully sent
                            // as long as *one* message succeeds. Is this correct? Or
                            // do we want each message to be separate? Is that a server
                            // side concern rather than a client side one?
                            //
                            // Should the server generate a message event per destination
                            // instead?
                            for to_address in message.mail_destination {
                                let queue_message  = QueuedMessage {
                                    message_id: message.header.id,
                                    to_address: to_address.value,
                                    ob_msg_template: message.message_template.clone(),
                                };

                                if let Err(err) = outbound_tx.send(queue_message).await {
                                    error!(?err, "transmission queue has died!");
                                    break 'outer;
                                }
                            }
                        }
                    }
                    Err(client_error) => {
                        error!(?client_error, "Unable to check for queued mail");
                    }
                }
            }
        }
    }
    info!("Stopped mail driver");
}

fn config_security_checks(cfg_path: &Path) -> bool {
    let cfg_path_str = cfg_path.to_string_lossy();

    if !cfg_path.exists() {
        // there's no point trying to start up if we can't read a usable config!
        error!(
            "Config missing from {} - cannot start up. Quitting.",
            cfg_path_str
        );
        false
    } else {
        let cfg_meta = match metadata(cfg_path) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Unable to read metadata for config file '{}' during security checks - {:?}",
                    cfg_path_str, e
                );
                return false;
            }
        };
        if !file_permissions_readonly(&cfg_meta) {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                cfg_path_str
                );
        }

        #[cfg(target_family = "unix")]
        if cfg_meta.uid() == get_current_uid() || cfg_meta.uid() == get_effective_uid() {
            warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                cfg_path_str
            );
        }

        true
    }
}

async fn driver_main(opt: Opt) -> Result<(), ()> {
    let mut f = match File::open(&opt.mail_sender_config) {
        Ok(f) => f,
        Err(e) => {
            error!(
                "Unable to open mail sender config from '{}' [{:?}] 🥺",
                &opt.mail_sender_config.display(),
                e
            );
            return Err(());
        }
    };

    let mut contents = String::new();
    if let Err(e) = f.read_to_string(&mut contents) {
        error!(
            "unable to read file '{}': {:?}",
            &opt.mail_sender_config.display(),
            e
        );
        return Err(());
    };

    let mail_config: Config = match toml::from_str(contents.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "Unable to parse config from '{}' error: {:?}",
                &opt.mail_sender_config.display(),
                e
            );
            return Err(());
        }
    };

    debug!(?mail_config);

    // Every 5 seconds.
    let expression = mail_config.schedule.as_deref().unwrap_or("*/5 * * * * * *");

    let schedule = match Schedule::from_str(expression) {
        Ok(s) => s,
        Err(_) => {
            error!("Failed to parse cron schedule expression");
            return Err(());
        }
    };

    let cb = match KanidmClientBuilder::new().read_options_from_optional_config(&opt.client_config)
    {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse {}", opt.client_config.to_string_lossy());
            return Err(());
        }
    };

    let rsclient = match cb.build() {
        Ok(rsc) => rsc,
        Err(_e) => {
            error!("Failed to build async client");
            return Err(());
        }
    };

    rsclient.set_token(mail_config.token.clone()).await;

    // Setup the connection pool
    let creds = Credentials::new(
        mail_config.mail_username.clone(),
        mail_config.mail_password.clone(),
    );

    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        match AsyncSmtpTransport::<Tokio1Executor>::relay(mail_config.mail_relay.as_str()) {
            Ok(mailer_builder) => mailer_builder.credentials(creds).build(),
            Err(err) => {
                error!(?err, "Unable to build mail transport");
                return Err(());
            }
        };

    // Channel for submission of mails that need to be sent
    let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_CAPACITY);

    // Channel for acknowledgement of messages that have been processed
    let (response_tx, mut response_rx) = mpsc::channel(CHANNEL_CAPACITY);

    // Control channel to signal when we need to shutdown. Only ever needs to queue 1 message
    // on shutdown.
    let (broadcast_tx, broadcast_rx) = broadcast::channel(1);

    let broadcast_rx_c = broadcast_tx.subscribe();

    // This task is what actually sends mail.
    let driver_handle = tokio::spawn(async move {
        mail_driver(
            broadcast_rx_c,
            &mailer,
            &mail_config,
            outbound_rx,
            response_tx,
        )
        .await
    });

    if let Some(to_address) = opt.test_email {
        let ob_msg_template = OutboundMessage::TestMessageV1 {
            display_name: "KANIDM MAIL SENDER TEST".into(),
        };

        let queue_message = QueuedMessage {
            message_id: Uuid::new_v4(),
            to_address,
            ob_msg_template,
        };

        if let Err(err) = outbound_tx.send(queue_message).await {
            error!(?err);
            return Err(());
        };

        if let Some(rsp) = response_rx.recv().await {
            if let Err(err) = rsp.status {
                error!(?err);
            } else {
                info!("Success!");
            }
        } else {
            // failed
            error!("response channel has died");
        };

        broadcast_tx
            .send(())
            .expect("Failed to trigger a clean shutdown!");
    } else {
        let checker_handle = tokio::spawn(async move {
            mail_checker(broadcast_rx, outbound_tx, response_rx, schedule, rsclient).await
        });

        loop {
            #[cfg(target_family = "unix")]
            {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::terminate();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::alarm();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::hangup();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                }
            }
            #[cfg(target_family = "windows")]
            {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                }
            }
        }

        broadcast_tx
            .send(())
            .expect("Failed to trigger a clean shutdown!");

        let _ = checker_handle.await;
    }

    // We're ready, lets go.

    let _ = driver_handle.await;

    // Done
    Ok(())
}

fn main() {
    let opt = Opt::parse();

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = if opt.debug {
        match EnvFilter::try_new("kanidm_client=debug,kanidm_mail_sender=debug,lettre=debug") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR! Unable to start tracing {e:?}");
                return;
            }
        }
    } else {
        match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::new("kanidm_client=warn,kanidm_mail_sender=info"),
        }
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    // Startup sanity checks.
    #[cfg(target_family = "unix")]
    if opt.skip_root_check {
        warn!("Skipping root user check, if you're running this for testing, ensure you clean up temporary files.")
    } else if get_current_uid() == 0
        || get_effective_uid() == 0
        || get_current_gid() == 0
        || get_effective_gid() == 0
    {
        error!("Refusing to run - this process must not operate as root.");
        return;
    };

    if !config_security_checks(&opt.client_config)
        || !config_security_checks(&opt.mail_sender_config)
    {
        return;
    }

    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to initialise tokio runtime!");

    if rt.block_on(async move { driver_main(opt).await }).is_err() {
        std::process::exit(1);
    };
}
