use crate::prelude::AuditScope;

use crate::actors::v1_read::QueryServerReadV1;
use crate::ldap::{LdapBoundToken, LdapResponseState};
use crate::prelude::*;
use core::pin::Pin;
use openssl::ssl::{Ssl, SslAcceptor, SslAcceptorBuilder};
use tokio_openssl::SslStream;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use ldap3_server::LdapCodec;
use std::marker::Unpin;
use std::net;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::trace;
use uuid::Uuid;

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

async fn client_process<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    mut r: FramedRead<R, LdapCodec>,
    mut w: FramedWrite<W, LdapCodec>,
    client_address: net::SocketAddr,
    qe_r_ref: &'static QueryServerReadV1,
) {
    // This is a connected client session. we need to associate some state to the session
    let mut session = LdapSession::new();
    // Now that we have the session we begin an event loop to process input OR we return.
    while let Some(Ok(protomsg)) = r.next().await {
        // Start the event
        let eventid = Uuid::new_v4();
        let mut audit = AuditScope::new("ldap_request_message", eventid, qe_r_ref.log_level);
        let uat = session.uat.clone();
        // I'd really have liked to have put this near the [LdapResponseState::Bind] but due to the handing of `audit` it isn't possible due to borrows, etc.
        security_info!(
            client_ip = %client_address.ip(),
            client_port = %client_address.port(),
            "LDAP client"
        );
        let qs_result = qe_r_ref
            .handle_ldaprequest(eventid, audit, protomsg, uat)
            .await;

        match qs_result {
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

/// TLS LDAP Listener, hands off to [client_process]
async fn tls_acceptor(
    listener: TcpListener,
    tls_parms: SslAcceptor,
    qe_r_ref: &'static QueryServerReadV1,
) {
    loop {
        match listener.accept().await {
            Ok((tcpstream, client_socket_addr)) => {
                // Start the event
                // From the parms we need to create an SslContext.
                let mut tlsstream = match Ssl::new(tls_parms.context())
                    .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
                {
                    Ok(ta) => ta,
                    Err(e) => {
                        error!("LDAP TLS setup error, continuing -> {:?}", e);
                        continue;
                    }
                };
                if let Err(e) = SslStream::accept(Pin::new(&mut tlsstream)).await {
                    error!("LDAP TLS accept error, continuing -> {:?}", e);
                    continue;
                };
                let (r, w) = tokio::io::split(tlsstream);
                let r = FramedRead::new(r, LdapCodec);
                let w = FramedWrite::new(w, LdapCodec);
                tokio::spawn(client_process(r, w, client_socket_addr, qe_r_ref));
            }
            Err(e) => {
                error!("LDAP acceptor error, continuing -> {:?}", e);
            }
        }
    }
}

/// Plain TCP LDAP Listener, hands off to [client_process]
async fn acceptor(listener: TcpListener, qe_r_ref: &'static QueryServerReadV1) {
    loop {
        match listener.accept().await {
            Ok((tcpstream, client_socket_addr)) => {
                // Start the event
                let (r, w) = tokio::io::split(tcpstream);
                let r = FramedRead::new(r, LdapCodec);
                let w = FramedWrite::new(w, LdapCodec);
                // Let it rip.
                tokio::spawn(client_process(r, w, client_socket_addr, qe_r_ref));
            }
            Err(e) => {
                error!("LDAP acceptor error, continuing -> {:?}", e);
            }
        }
    }
}

pub(crate) async fn create_ldap_server(
    address: &str,
    opt_tls_params: Option<SslAcceptorBuilder>,
    qe_r_ref: &'static QueryServerReadV1,
) -> Result<(), ()> {
    if address.starts_with(":::") {
        // takes :::xxxx to xxxx
        let port = address.replacen(":::", "", 1);
        eprintln!("Address '{}' looks like an attempt to wildcard bind with IPv6 on port {} - please try using ldapbindaddress = '[::]:{}'", address, port, port);
    };

    let addr = net::SocketAddr::from_str(address).map_err(|e| {
        eprintln!("Could not parse ldap server address {} -> {:?}", address, e);
    })?;

    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        eprintln!(
            "Could not bind to ldap server address {} -> {:?}",
            address, e
        );
    })?;

    match opt_tls_params {
        Some(tls_params) => {
            eprintln!("Starting LDAPS interface ldaps://{} ...", address);
            let tls_parms = tls_params.build();
            tokio::spawn(tls_acceptor(listener, tls_parms, qe_r_ref));
        }
        None => {
            eprintln!("Starting LDAP interface ldap://{} ...", address);
            tokio::spawn(acceptor(listener, qe_r_ref));
        }
    }

    info!("Created LDAP interface");
    Ok(())
}
