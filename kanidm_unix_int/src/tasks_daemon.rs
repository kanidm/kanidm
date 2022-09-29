#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::ffi::CString;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::Duration;
use std::{fs, io};

use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{HomeDirectoryInfo, TaskRequest, TaskResponse};
use libc::{lchown, umask};
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use tokio::net::UnixStream;
use tokio::time;
use tokio_util::codec::{Decoder, Encoder, Framed};
use users::{get_effective_gid, get_effective_uid};

struct TaskCodec;

impl Decoder for TaskCodec {
    type Error = io::Error;
    type Item = TaskRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<TaskRequest>(&src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<TaskResponse> for TaskCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: TaskResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send request -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl TaskCodec {
    fn new() -> Self {
        TaskCodec
    }
}

fn create_home_directory(info: &HomeDirectoryInfo, home_prefix: &str) -> Result<(), String> {
    // Final sanity check to prevent certain classes of attacks.
    let name = info
        .name
        .trim_start_matches('.')
        .replace("/", "")
        .replace("\\", "");

    let home_prefix_path = Path::new(home_prefix);

    // Does our home_prefix actually exist?
    if !home_prefix_path.exists() || !home_prefix_path.is_dir() {
        return Err("Invalid home_prefix from configuration".to_string());
    }

    // Actually process the request here.
    let hd_path_raw = format!("{}{}", home_prefix, name);
    let hd_path = Path::new(&hd_path_raw);

    // Assert the resulting named home path is consistent and correct.
    if let Some(pp) = hd_path.parent() {
        if pp != home_prefix_path {
            return Err("Invalid home directory name - not within home_prefix".to_string());
        }
    } else {
        return Err("Invalid/Corrupt home directory path - no prefix found".to_string());
    }

    let hd_path_os =
        CString::new(hd_path_raw.clone()).map_err(|_| "Unable to create c-string".to_string())?;

    // Does the home directory exist?
    if !hd_path.exists() {
        // Set a umask
        let before = unsafe { umask(0o0027) };
        // TODO: Should we copy content from /etc/skel?
        // Create the dir
        if let Err(e) = fs::create_dir_all(hd_path) {
            let _ = unsafe { umask(before) };
            return Err(format!("{:?}", e));
        }
        let _ = unsafe { umask(before) };

        // Change the owner to the gid - remember, kanidm ONLY has gid's, the uid is implied.

        if unsafe { lchown(hd_path_os.as_ptr(), info.gid, info.gid) } != 0 {
            return Err("Unable to set ownership".to_string());
        }
    }

    let name_rel_path = Path::new(&name);
    // Does the aliases exist
    for alias in info.aliases.iter() {
        // Sanity check the alias.
        // let alias = alias.replace(".", "").replace("/", "").replace("\\", "");
        let alias = alias
            .trim_start_matches('.')
            .replace("/", "")
            .replace("\\", "");
        let alias_path_raw = format!("{}{}", home_prefix, alias);
        let alias_path = Path::new(&alias_path_raw);

        // Assert the resulting alias path is consistent and correct.
        if let Some(pp) = alias_path.parent() {
            if pp != home_prefix_path {
                return Err("Invalid home directory alias - not within home_prefix".to_string());
            }
        } else {
            return Err("Invalid/Corrupt alias directory path - no prefix found".to_string());
        }

        if alias_path.exists() {
            let attr = match fs::symlink_metadata(alias_path) {
                Ok(a) => a,
                Err(e) => {
                    return Err(format!("{:?}", e));
                }
            };

            if attr.file_type().is_symlink() {
                // Probably need to update it.
                if let Err(e) = fs::remove_file(alias_path) {
                    return Err(format!("{:?}", e));
                }
                if let Err(e) = symlink(name_rel_path, alias_path) {
                    return Err(format!("{:?}", e));
                }
            }
        } else {
            // Does not exist. Create.
            if let Err(e) = symlink(name_rel_path, alias_path) {
                return Err(format!("{:?}", e));
            }
        }
    }
    Ok(())
}

async fn handle_tasks(stream: UnixStream, home_prefix: &str) {
    let mut reqs = Framed::new(stream, TaskCodec::new());

    loop {
        match reqs.next().await {
            Some(Ok(TaskRequest::HomeDirectory(info))) => {
                debug!("Received task -> HomeDirectory({:?})", info);

                let resp = match create_home_directory(&info, home_prefix) {
                    Ok(()) => TaskResponse::Success,
                    Err(msg) => TaskResponse::Error(msg),
                };

                // Now send a result.
                if let Err(e) = reqs.send(resp).await {
                    error!("Error -> {:?}", e);
                    return;
                }
                // All good, loop.
            }
            other => {
                error!("Error -> {:?}", other);
                return;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // let cuid = get_current_uid();
    // let cgid = get_current_gid();
    // We only need to check effective id
    let ceuid = get_effective_uid();
    let cegid = get_effective_gid();

    if ceuid != 0 || cegid != 0 {
        eprintln!("Refusing to run - this process *MUST* operate as root.");
        std::process::exit(1);
    }

    tracing_forest::worker_task()
        .set_global(true)
        // Fall back to stderr
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| {
            subscriber.with(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("info"))
                    .expect("Failed to init envfilter"),
            )
        })
        .on(async {
            let unixd_path = Path::new(DEFAULT_CONFIG_PATH);
            let unixd_path_str = match unixd_path.to_str() {
                Some(cps) => cps,
                None => {
                    error!("Unable to turn unixd_path to str");
                    std::process::exit(1);
                }
            };

            let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config(unixd_path) {
                Ok(v) => v,
                Err(_) => {
                    error!("Failed to parse {}", unixd_path_str);
                    std::process::exit(1);
                }
            };

            let task_sock_path = cfg.task_sock_path.clone();
            debug!("Attempting to use {} ...", task_sock_path);

            let server = async move {
                loop {
                    info!("Attempting to connect to kanidm_unixd ...");
                    // Try to connect to the daemon.
                    match UnixStream::connect(&task_sock_path).await {
                        // Did we connect?
                        Ok(stream) => {
                            info!("Found kanidm_unixd, waiting for tasks ...");
                            // Yep! Now let the main handler do it's job.
                            // If it returns (dc, etc, then we loop and try again).
                            handle_tasks(stream, &cfg.home_prefix).await;
                        }
                        Err(e) => {
                            error!("Unable to find kanidm_unixd, sleeping ...");
                            debug!("\\---> {:?}", e);
                            // Back off.
                            time::sleep(Duration::from_millis(5000)).await;
                        }
                    }
                }
            };

            server.await;
        })
        .await;
}
