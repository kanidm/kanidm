use crate::actors::v1_write::QueryServerWriteV1;
use crate::CoreAction;
use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{span, Level};
use users::get_current_uid;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub enum AdminTaskRequest {
    RecoverAccount { name: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AdminTaskResponse {
    RecoverAccount { password: String },
    Error,
}

#[derive(Default)]
pub struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = AdminTaskResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<AdminTaskResponse>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<AdminTaskRequest> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: AdminTaskRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

#[derive(Default)]
struct ServerCodec;

impl Decoder for ServerCodec {
    type Error = io::Error;
    type Item = AdminTaskRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<AdminTaskRequest>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<AdminTaskResponse> for ServerCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: AdminTaskResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

pub(crate) struct AdminActor;

impl AdminActor {
    pub async fn create_admin_sock(
        sock_path: &str,
        server: &'static QueryServerWriteV1,
        mut broadcast_rx: broadcast::Receiver<CoreAction>,
    ) -> Result<tokio::task::JoinHandle<()>, ()> {
        debug!("🧹 Cleaning up sockets from previous invocations");
        rm_if_exist(sock_path);

        // Setup the unix socket.
        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                error!(err = ?e, "Failed to bind UNIX socket {}", sock_path);
                return Err(());
            }
        };

        // what is the uid we are running as?
        let cuid = get_current_uid();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(action) = broadcast_rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                        }
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((socket, _addr)) => {
                                // Assert that the incoming connection is from root or
                                // our own uid.
                                // ⚠️  This underpins the security of this socket ⚠️
                                if let Ok(ucred) = socket.peer_cred() {
                                    let incoming_uid = ucred.uid();
                                    if incoming_uid == 0 || incoming_uid == cuid {
                                        // all good!
                                        info!(pid = ?ucred.pid(), "Allowing admin socket access");
                                    } else {
                                        warn!(%incoming_uid, "unauthorised user");
                                        continue;
                                    }
                                } else {
                                    error!("unable to determine peer credentials");
                                    continue;
                                };

                                // spawn the worker.
                                let _ = tokio::spawn(async move {
                                    if let Err(e) = handle_client(socket, server).await {
                                        error!(err = ?e, "admin client error");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(err = ?e, "admin socket accept error");
                            }
                        }
                    }
                }
            }
            info!("Stopped AdminActor");
        });
        Ok(handle)
    }
}

fn rm_if_exist(p: &str) {
    if Path::new(p).exists() {
        debug!("Removing requested file {:?}", p);
        let _ = std::fs::remove_file(p).map_err(|e| {
            error!(
                "Failure while attempting to attempting to remove {:?} -> {:?}",
                p, e
            );
        });
    } else {
        debug!("Path {:?} doesn't exist, not attempting to remove.", p);
    }
}

async fn handle_client(
    sock: UnixStream,
    server: &'static QueryServerWriteV1,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted admin socket connection");

    let mut reqs = Framed::new(sock, ServerCodec::default());

    trace!("Waiting for requests ...");
    while let Some(Ok(req)) = reqs.next().await {
        // Setup the logging span
        let eventid = Uuid::new_v4();
        let nspan = span!(Level::INFO, "handle_admin_client_request", uuid = ?eventid);
        let _span = nspan.enter();

        let resp = match req {
            AdminTaskRequest::RecoverAccount { name } => {
                match server.handle_admin_recover_account(name, eventid).await {
                    Ok(password) => AdminTaskResponse::RecoverAccount { password },
                    Err(e) => {
                        error!(err = ?e, "error during recover-account");
                        AdminTaskResponse::Error
                    }
                }
            }
        };
        reqs.send(resp).await?;
        reqs.flush().await?;
        trace!("flushed response!");
    }

    debug!("Disconnecting client ...");
    Ok(())
}
