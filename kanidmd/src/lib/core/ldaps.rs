use crate::actors::v1_read::{LdapRequestMessage, QueryServerReadV1};
use crate::ldap::{LdapBoundToken, LdapResponseState};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder};

use actix::prelude::*;
use futures_util::stream::StreamExt;
use ldap3_server::simple::*;
use ldap3_server::LdapCodec;
// use std::convert::TryFrom;
use std::io;
use std::marker::Unpin;
use std::net;
use std::str::FromStr;
use tokio::io::{AsyncWrite, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::FramedRead;
use uuid::Uuid;

struct LdapReq(pub LdapMsg);

impl Message for LdapReq {
    type Result = Result<(), ()>;
}

pub struct LdapServer {
    qe_r: Addr<QueryServerReadV1>,
}

pub struct LdapSession<T>
where
    T: AsyncWrite + Unpin,
{
    qe_r: Addr<QueryServerReadV1>,
    framed: actix::io::FramedWrite<WriteHalf<T>, LdapCodec>,
    uat: Option<LdapBoundToken>,
}

impl<T> Actor for LdapSession<T>
where
    T: 'static + AsyncWrite + Unpin,
{
    type Context = actix::Context<Self>;
}

impl<T> actix::io::WriteHandler<io::Error> for LdapSession<T> where T: 'static + AsyncWrite + Unpin {}

impl<T> Handler<LdapReq> for LdapSession<T>
where
    T: 'static + AsyncWrite + Unpin,
{
    type Result = ResponseActFuture<Self, Result<(), ()>>;

    fn handle(&mut self, msg: LdapReq, ctx: &mut Self::Context) -> Self::Result {
        let protomsg = msg.0;
        // Transform the LdapMsg to something the query server can work with.

        // Because of the way these futures works, it's up to the qe_r to manage
        // a lot of this, so we just palm off the processing to the thead pool.
        let eventid = Uuid::new_v4();
        let uat = self.uat.clone();
        let qsf = self.qe_r.send(LdapRequestMessage {
            eventid,
            protomsg,
            uat,
        });
        let qsf = actix::fut::wrap_future::<_, Self>(qsf);

        let f = qsf.map(|result, actor, ctx| {
            match result {
                Ok(Some(LdapResponseState::Unbind)) => ctx.stop(),
                Ok(Some(LdapResponseState::Disconnect(r))) => {
                    actor.framed.write(r);
                    ctx.stop()
                }
                Ok(Some(LdapResponseState::Bind(uat, r))) => {
                    actor.uat = Some(uat);
                    actor.framed.write(r);
                }
                Ok(Some(LdapResponseState::Respond(r))) => {
                    actor.framed.write(r);
                }
                _ => {
                    error!("Internal server error");
                    ctx.stop();
                }
            };
            Ok(())
        });

        Box::new(f)
    }
}

impl<T> StreamHandler<Result<LdapMsg, io::Error>> for LdapSession<T>
where
    T: 'static + AsyncWrite + Unpin,
{
    fn handle(&mut self, msg: Result<LdapMsg, io::Error>, ctx: &mut Self::Context) {
        match msg {
            Ok(lm) => match ctx.address().try_send(LdapReq(lm)) {
                // It's queued, we are done.
                Ok(_) => {}
                Err(_) => {
                    error!("Too many queue msgs for connection");
                    ctx.stop()
                }
            },
            Err(_) => {
                error!("Io error");
                ctx.stop()
            }
        }
    }
}

impl<T> LdapSession<T>
where
    T: 'static + AsyncWrite + Unpin,
{
    pub fn new(
        framed: actix::io::FramedWrite<WriteHalf<T>, LdapCodec>,
        qe_r: Addr<QueryServerReadV1>,
    ) -> Self {
        LdapSession {
            qe_r,
            framed,
            uat: None,
        }
    }
}

impl Actor for LdapServer {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "()")]
struct TcpConnect(pub TcpStream, pub net::SocketAddr);

impl Handler<TcpConnect> for LdapServer {
    type Result = ();
    fn handle(&mut self, msg: TcpConnect, _: &mut Context<Self>) {
        LdapSession::create(move |ctx| {
            let (r, w) = tokio::io::split(msg.0);
            LdapSession::add_stream(FramedRead::new(r, LdapCodec), ctx);
            LdapSession::new(
                actix::io::FramedWrite::new(w, LdapCodec, ctx),
                self.qe_r.clone(),
            )
        });
    }
}

#[derive(Message)]
#[rtype(result = "Result<(), ()>")]
struct TlsConnect(pub &'static SslAcceptor, pub TcpStream, pub net::SocketAddr);

impl Handler<TlsConnect> for LdapServer {
    type Result = ResponseActFuture<Self, Result<(), ()>>;
    fn handle(&mut self, msg: TlsConnect, _: &mut Context<Self>) -> Self::Result {
        let qsf = tokio_openssl::accept(msg.0, msg.1);
        let qsf = actix::fut::wrap_future::<_, Self>(qsf);

        let f = qsf.map(|result, actor, _ctx| {
            result
                .map(|tlsstream| {
                    LdapSession::create(move |ctx| {
                        let (r, w) = tokio::io::split(tlsstream);
                        LdapSession::add_stream(FramedRead::new(r, LdapCodec), ctx);
                        LdapSession::new(
                            actix::io::FramedWrite::new(w, LdapCodec, ctx),
                            actor.qe_r.clone(),
                        )
                    });
                    ()
                })
                .map_err(|_| {
                    error!("invalid tls handshake");
                    ()
                })
        });

        Box::new(f)
    }
}

pub(crate) async fn create_ldap_server(
    address: &str,
    opt_tls_params: Option<SslAcceptorBuilder>,
    qe_r: Addr<QueryServerReadV1>,
) -> Result<(), ()> {
    let addr = net::SocketAddr::from_str(address).map_err(|e| {
        error!("Could not parse ldap server address {} -> {:?}", address, e);
        ()
    })?;

    let listener = Box::new(TcpListener::bind(&addr).await.unwrap());

    match opt_tls_params {
        Some(tls_params) => {
            info!("Starting LDAPS interface ldaps://{} ...", address);
            LdapServer::create(move |ctx| {
                let acceptor = Box::new(tls_params.build());
                let lacceptor = Box::leak(acceptor) as &'static _;

                ctx.add_message_stream(Box::leak(listener).incoming().map(move |st| {
                    let st = st.unwrap();
                    let addr = st.peer_addr().unwrap();
                    TlsConnect(lacceptor, st, addr)
                }));
                LdapServer { qe_r }
            });
        }
        None => {
            info!("Starting LDAP interface ldap://{} ...", address);
            LdapServer::create(move |ctx| {
                ctx.add_message_stream(Box::leak(listener).incoming().map(|st| {
                    let st = st.unwrap();
                    let addr = st.peer_addr().unwrap();
                    TcpConnect(st, addr)
                }));
                LdapServer { qe_r }
            });
        }
    }

    info!("Created LDAP interface");
    Ok(())
}
