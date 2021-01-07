use crate::actors::v1_read::{LdapRequestMessage, QueryServerReadV1};
use crate::ldap::{LdapBoundToken, LdapResponseState};
use core::pin::Pin;
use openssl::ssl::{Ssl, SslAcceptor, SslAcceptorBuilder};
use tokio_openssl::SslStream;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
// use ldap3_server::simple::*;
use ldap3_server::proto::LdapMsg;
use ldap3_server::LdapCodec;
// use std::convert::TryFrom;
use std::marker::Unpin;
use std::net;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_util::codec::{FramedRead, FramedWrite};
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

async fn client_write_process<W: AsyncWrite + Unpin>(
    mut w: FramedWrite<W, LdapCodec>,
    mut async_rx: UnboundedReceiver<LdapMsg>,
) {
    while let Some(rmsg) = async_rx.recv().await {
        if w.send(rmsg).await.is_err() {
            // This will close the channel, so the reader will now fail and close.
            return;
        }
    }
}

async fn client_read_process<R: AsyncRead + Unpin>(
    mut r: FramedRead<R, LdapCodec>,
    async_tx: UnboundedSender<LdapMsg>,
    _paddr: net::SocketAddr,
    qe_r_ref: &'static QueryServerReadV1,
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
        let qs_result = qe_r_ref
            .handle_ldaprequest(LdapRequestMessage {
                eventid,
                protomsg,
                uat,
            })
            .await;

        match qs_result {
            Some(LdapResponseState::Unbind) => return,
            Some(LdapResponseState::Disconnect(rmsg)) => {
                if async_tx.send(rmsg).is_err() {
                    break;
                }
                break;
            }
            Some(LdapResponseState::Bind(uat, rmsg)) => {
                session.uat = Some(uat);
                if async_tx.send(rmsg).is_err() {
                    break;
                }
            }
            Some(LdapResponseState::Respond(rmsg)) => {
                if async_tx.send(rmsg).is_err() {
                    break;
                }
            }
            Some(LdapResponseState::MultiPartResponse(v)) => {
                for rmsg in v.into_iter() {
                    if async_tx.send(rmsg).is_err() {
                        break;
                    }
                }
            }
            Some(LdapResponseState::BindMultiPartResponse(uat, v)) => {
                session.uat = Some(uat);
                for rmsg in v.into_iter() {
                    if async_tx.send(rmsg).is_err() {
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
    // We now are leaving, so any cleanup done here.
}

async fn tls_acceptor(
    listener: TcpListener,
    tls_parms: SslAcceptor,
    qe_r_ref: &'static QueryServerReadV1,
) {
    loop {
        match listener.accept().await {
            Ok((tcpstream, paddr)) => {
                // From the parms we need to create an SslContext.
                let mut tlsstream = match Ssl::new(tls_parms.context())
                    .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
                {
                    Ok(ta) => ta,
                    Err(e) => {
                        error!("tls setup error, continuing -> {:?}", e);
                        continue;
                    }
                };
                if let Err(e) = SslStream::accept(Pin::new(&mut tlsstream)).await {
                    error!("tls accept error, continuing -> {:?}", e);
                    continue;
                };
                let (r, w) = tokio::io::split(tlsstream);
                let r = FramedRead::new(r, LdapCodec);
                let w = FramedWrite::new(w, LdapCodec);
                let (async_tx, async_rx) = unbounded_channel();

                tokio::spawn(client_write_process(w, async_rx));
                tokio::spawn(client_read_process(r, async_tx, paddr, qe_r_ref));
            }
            Err(e) => {
                error!("acceptor error, continuing -> {:?}", e);
            }
        }
    }
}

async fn acceptor(listener: TcpListener, qe_r_ref: &'static QueryServerReadV1) {
    loop {
        match listener.accept().await {
            Ok((tcpstream, paddr)) => {
                let (r, w) = tokio::io::split(tcpstream);
                let r = FramedRead::new(r, LdapCodec);
                let w = FramedWrite::new(w, LdapCodec);
                // Let it rip.
                let (async_tx, async_rx) = unbounded_channel();
                tokio::spawn(client_write_process(w, async_rx));
                tokio::spawn(client_read_process(r, async_tx, paddr, qe_r_ref));
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
    qe_r_ref: &'static QueryServerReadV1,
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
            tokio::spawn(tls_acceptor(listener, tls_parms, qe_r_ref));
        }
        None => {
            info!("Starting LDAP interface ldap://{} ...", address);
            tokio::spawn(acceptor(listener, qe_r_ref));
        }
    }

    info!("Created LDAP interface");
    Ok(())
}
