use crate::actors::v1_read::{LdapRequestMessage, QueryServerReadV1};
use crate::ldap::{LdapBoundToken, LdapResponseState};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder};

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use ldap3_server::simple::*;
use ldap3_server::LdapCodec;
// use std::convert::TryFrom;
use std::io;
use std::marker::Unpin;
use std::net;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite};
use uuid::Uuid;

use actix::prelude::Addr;

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
    paddr: net::SocketAddr,
    qe_r: Addr<QueryServerReadV1>,
) {
    // This is a connected client session. we need to associate some state to the
    // session
    let mut session = LdapSession::new();
    // Now that we have the session we begin an event loop to process input OR
    // we return.
    while let Some(Ok(protomsg)) = r.next().await {
        // Start the event
        let eventid = Uuid::new_v4();
        let uat = session.uat.clone();
        let qs_result = qe_r
            .send(LdapRequestMessage {
                eventid,
                protomsg,
                uat,
            })
            .await;

        match qs_result {
            Ok(Some(LdapResponseState::Unbind)) => return,
            Ok(Some(LdapResponseState::Disconnect(rmsg))) => {
                if let Err(_) = w.send(rmsg).await {
                    break;
                }
                break;
            }
            Ok(Some(LdapResponseState::Bind(uat, rmsg))) => {
                session.uat = Some(uat);
                if let Err(_) = w.send(rmsg).await {
                    break;
                }
            }
            Ok(Some(LdapResponseState::Respond(rmsg))) => {
                if let Err(_) = w.send(rmsg).await {
                    break;
                }
            }
            Ok(Some(LdapResponseState::MultiPartResponse(v))) => {
                for rmsg in v.into_iter() {
                    if let Err(_) = w.send(rmsg).await {
                        break;
                    }
                }
            }
            Ok(Some(LdapResponseState::BindMultiPartResponse(uat, v))) => {
                session.uat = Some(uat);
                for rmsg in v.into_iter() {
                    if let Err(_) = w.send(rmsg).await {
                        break;
                    }
                }
            }
            Ok(None) | Err(_) => {
                error!("Internal server error");
                break;
            }
        };
    }
    // We now are leaving, so any cleanup done here.
}

async fn tls_acceptor(
    mut listener: TcpListener,
    tls_parms: SslAcceptor,
    qe_r: Addr<QueryServerReadV1>,
) {
    // Do we need to do the silly ssl leak?
    loop {
        match listener.accept().await {
            Ok((tcpstream, paddr)) => {
                let res = tokio_openssl::accept(&tls_parms, tcpstream).await;
                let tlsstream = match res {
                    Ok(ts) => ts,
                    Err(e) => {
                        error!("tls handshake error, continuing -> {:?}", e);
                        continue;
                    }
                };
                let (r, w) = tokio::io::split(tlsstream);
                let r = FramedRead::new(r, LdapCodec);
                let w = FramedWrite::new(w, LdapCodec);
                let cqe_r = qe_r.clone();
                tokio::spawn(client_process(r, w, paddr, cqe_r));
            }
            Err(e) => {
                error!("acceptor error, continuing -> {:?}", e);
            }
        }
    }
}

async fn acceptor(mut listener: TcpListener, qe_r: Addr<QueryServerReadV1>) {
    loop {
        match listener.accept().await {
            Ok((tcpstream, paddr)) => {
                let cqe_r = qe_r.clone();
                let (r, w) = tokio::io::split(tcpstream);
                let r = FramedRead::new(r, LdapCodec);
                let w = FramedWrite::new(w, LdapCodec);
                // Let it rip.
                tokio::spawn(client_process(r, w, paddr, cqe_r));
            }
            Err(e) => {
                error!("acceptor error, continuing -> {:?}", e);
            }
        }
    }
}

pub(crate) async fn create_ldap_server(
    address: &str,
    opt_tls_params: Option<SslAcceptorBuilder>,
    qe_r: Addr<QueryServerReadV1>,
) -> Result<(), ()> {
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
            info!("Starting LDAPS interface ldaps://{} ...", address);
            let tls_parms = tls_params.build();
            tokio::spawn(tls_acceptor(listener, tls_parms, qe_r));
        }
        None => {
            info!("Starting LDAP interface ldap://{} ...", address);
            tokio::spawn(acceptor(listener, qe_r));
        }
    }

    info!("Created LDAP interface");
    Ok(())
}
