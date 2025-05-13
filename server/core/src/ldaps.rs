use crate::actors::QueryServerReadV1;
use crate::CoreAction;
use cidr::IpCidr;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use haproxy_protocol::{ProxyHdrV2, RemoteAddress};
use kanidmd_lib::idm::ldap::{LdapBoundToken, LdapResponseState};
use kanidmd_lib::prelude::*;
use ldap3_proto::proto::LdapMsg;
use ldap3_proto::LdapCodec;
use openssl::ssl::{Ssl, SslAcceptor};
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_openssl::SslStream;
use tokio_util::codec::{FramedRead, FramedWrite};

struct LdapSession {
    uat: Option<LdapBoundToken>,
}

impl LdapSession {
    fn new() -> Self {
        LdapSession {
            // We start un-authenticated
            uat: None,
        }
    }
}

#[instrument(name = "ldap-request", skip(client_address, qe_r_ref))]
async fn client_process_msg(
    uat: Option<LdapBoundToken>,
    client_address: SocketAddr,
    protomsg: LdapMsg,
    qe_r_ref: &'static QueryServerReadV1,
) -> Option<LdapResponseState> {
    let eventid = sketching::tracing_forest::id();
    security_info!(
        client_ip = %client_address.ip(),
        client_port = %client_address.port(),
        "LDAP client"
    );
    qe_r_ref
        .handle_ldaprequest(eventid, protomsg, uat, client_address.ip())
        .await
}

async fn client_process<STREAM>(
    stream: STREAM,
    client_address: SocketAddr,
    connection_address: SocketAddr,
    qe_r_ref: &'static QueryServerReadV1,
) where
    STREAM: AsyncRead + AsyncWrite,
{
    let (r, w) = tokio::io::split(stream);
    let mut r = FramedRead::new(r, LdapCodec::default());
    let mut w = FramedWrite::new(w, LdapCodec::default());

    // This is a connected client session. we need to associate some state to the session
    let mut session = LdapSession::new();
    // Now that we have the session we begin an event loop to process input OR we return.
    while let Some(Ok(protomsg)) = r.next().await {
        // Start the event
        let uat = session.uat.clone();
        let caddr = client_address;

        debug!(?client_address, ?connection_address);

        match client_process_msg(uat, caddr, protomsg, qe_r_ref).await {
            // I'd really have liked to have put this near the [LdapResponseState::Bind] but due
            // to the handing of `audit` it isn't possible due to borrows, etc.
            Some(LdapResponseState::Unbind) => return,
            Some(LdapResponseState::Disconnect(rmsg)) => {
                if w.send(rmsg).await.is_err() {
                    break;
                }
                break;
            }
            Some(LdapResponseState::Bind(uat, rmsg)) => {
                session.uat = Some(uat);
                if w.send(rmsg).await.is_err() {
                    break;
                }
            }
            Some(LdapResponseState::Respond(rmsg)) => {
                if w.send(rmsg).await.is_err() {
                    break;
                }
            }
            Some(LdapResponseState::MultiPartResponse(v)) => {
                for rmsg in v.into_iter() {
                    if w.send(rmsg).await.is_err() {
                        break;
                    }
                }
            }
            Some(LdapResponseState::BindMultiPartResponse(uat, v)) => {
                session.uat = Some(uat);
                for rmsg in v.into_iter() {
                    if w.send(rmsg).await.is_err() {
                        break;
                    }
                }
            }
            None => {
                error!("Internal server error");
                break;
            }
        };
    }
}

async fn client_tls_accept(
    stream: TcpStream,
    tls_acceptor: SslAcceptor,
    connection_addr: SocketAddr,
    qe_r_ref: &'static QueryServerReadV1,
    trusted_proxy_v2_ips: Option<Arc<Vec<IpCidr>>>,
) {
    let enable_proxy_v2_hdr = trusted_proxy_v2_ips
        .map(|trusted| {
            trusted
                .iter()
                .any(|ip_cidr| ip_cidr.contains(&connection_addr.ip()))
        })
        .unwrap_or_default();

    let (stream, client_addr) = if enable_proxy_v2_hdr {
        match ProxyHdrV2::parse_from_read(stream).await {
            Ok((stream, hdr)) => {
                let remote_socket_addr = match hdr.to_remote_addr() {
                    RemoteAddress::Local => {
                        debug!("PROXY protocol liveness check - will not contain client data");
                        return;
                    }
                    RemoteAddress::TcpV4 { src, dst: _ } => SocketAddr::from(src),
                    RemoteAddress::TcpV6 { src, dst: _ } => SocketAddr::from(src),
                    remote_addr => {
                        error!(?remote_addr, "remote address in proxy header is invalid");
                        return;
                    }
                };

                (stream, remote_socket_addr)
            }
            Err(err) => {
                error!(?connection_addr, ?err, "Unable to process proxy v2 header");
                return;
            }
        }
    } else {
        (stream, connection_addr)
    };

    // Start the event
    // From the parameters we need to create an SslContext.
    let mut tlsstream = match Ssl::new(tls_acceptor.context())
        .and_then(|tls_obj| SslStream::new(tls_obj, stream))
    {
        Ok(ta) => ta,
        Err(err) => {
            error!(?err, %client_addr, %connection_addr, "LDAP TLS setup error");
            return;
        }
    };
    if let Err(err) = SslStream::accept(Pin::new(&mut tlsstream)).await {
        error!(?err, %client_addr, %connection_addr, "LDAP TLS accept error");
        return;
    };

    tokio::spawn(client_process(
        tlsstream,
        client_addr,
        connection_addr,
        qe_r_ref,
    ));
}

/// TLS LDAP Listener, hands off to [client_tls_accept]
async fn ldap_tls_acceptor(
    listener: TcpListener,
    mut tls_acceptor: SslAcceptor,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
    mut tls_acceptor_reload_rx: mpsc::Receiver<SslAcceptor>,
    trusted_proxy_v2_ips: Option<Arc<Vec<IpCidr>>>,
) {
    loop {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => break,
                }
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcpstream, client_socket_addr)) => {
                        let clone_tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(client_tls_accept(tcpstream, clone_tls_acceptor, client_socket_addr, qe_r_ref, trusted_proxy_v2_ips.clone()));
                    }
                    Err(err) => {
                        warn!(?err, "LDAP acceptor error, continuing");
                    }
                }
            }
            Some(mut new_tls_acceptor) = tls_acceptor_reload_rx.recv() => {
                std::mem::swap(&mut tls_acceptor, &mut new_tls_acceptor);
                info!("Reloaded ldap tls acceptor");
            }
        }
    }
    info!("Stopped {}", super::TaskName::LdapActor);
}

/// PLAIN LDAP Listener, hands off to [client_process]
async fn ldap_plaintext_acceptor(
    listener: TcpListener,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
) {
    loop {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => break,
                }
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcpstream, client_socket_addr)) => {
                        tokio::spawn(client_process(tcpstream, client_socket_addr, client_socket_addr, qe_r_ref));
                    }
                    Err(e) => {
                        error!("LDAP acceptor error, continuing -> {:?}", e);
                    }
                }
            }
        }
    }
    info!("Stopped {}", super::TaskName::LdapActor);
}

pub(crate) async fn create_ldap_server(
    address: &str,
    opt_ssl_acceptor: Option<SslAcceptor>,
    qe_r_ref: &'static QueryServerReadV1,
    rx: broadcast::Receiver<CoreAction>,
    tls_acceptor_reload_rx: mpsc::Receiver<SslAcceptor>,
    trusted_proxy_v2_ips: Option<Vec<IpCidr>>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    if address.starts_with(":::") {
        // takes :::xxxx to xxxx
        let port = address.replacen(":::", "", 1);
        error!("Address '{}' looks like an attempt to wildcard bind with IPv6 on port {} - please try using ldapbindaddress = '[::]:{}'", address, port, port);
    };

    let addr = SocketAddr::from_str(address).map_err(|e| {
        error!("Could not parse LDAP server address {} -> {:?}", address, e);
    })?;

    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        error!(
            "Could not bind to LDAP server address {} -> {:?}",
            address, e
        );
    })?;

    let trusted_proxy_v2_ips = trusted_proxy_v2_ips.map(Arc::new);

    let ldap_acceptor_handle = match opt_ssl_acceptor {
        Some(ssl_acceptor) => {
            info!("Starting LDAPS interface ldaps://{} ...", address);

            tokio::spawn(ldap_tls_acceptor(
                listener,
                ssl_acceptor,
                qe_r_ref,
                rx,
                tls_acceptor_reload_rx,
                trusted_proxy_v2_ips,
            ))
        }
        None => tokio::spawn(ldap_plaintext_acceptor(listener, qe_r_ref, rx)),
    };

    info!("Created LDAP interface");
    Ok(ldap_acceptor_handle)
}
