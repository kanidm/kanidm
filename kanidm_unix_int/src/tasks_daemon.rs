#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate log;

use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use std::os::unix::fs::symlink;

use libc::{lchown, umask};
use std::ffi::CString;

use bytes::{BufMut, BytesMut};
use futures::SinkExt;
use futures::StreamExt;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::time;
use tokio_util::codec::Framed;
use tokio_util::codec::{Decoder, Encoder};

use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{HomeDirectoryInfo, TaskRequest, TaskResponse};

struct TaskCodec;

impl Decoder for TaskCodec {
    type Item = TaskRequest;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_cbor::from_slice::<TaskRequest>(&src) {
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
        let data = serde_cbor::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::new(io::ErrorKind::Other, "CBOR encode error")
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

fn create_home_directory(info: &HomeDirectoryInfo) -> Result<(), String> {
    // Final sanity check to prevent certain classes of attacks.
    let name = info
        .name
        .replace(".", "")
        .replace("/", "")
        .replace("\\", "");
    // Note, due to how this works, we can't remove '/'. But we still want to stop traversals.
    let path = info.path.replace(".", "").replace("\\", "");

    // Actually process the request here.
    let hd_path_raw = format!("{}{}", path, name);
    let hd_path = Path::new(&hd_path_raw);

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

        // Change the owner/gid

        if unsafe { lchown(hd_path_os.as_ptr(), info.gid, info.gid) } != 0 {
            return Err("Unable to set ownership".to_string());
        }
    }

    let name_rel_path = Path::new(&name);
    // Does the aliases exist
    for alias in info.aliases.iter() {
        // Sanity check the alias.
        let alias = alias.replace(".", "").replace("/", "").replace("\\", "");
        let alias_path_raw = format!("{}{}", path, alias);
        let alias_path = Path::new(&alias_path_raw);
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

async fn handle_tasks(stream: UnixStream) {
    let mut reqs = Framed::new(stream, TaskCodec::new());

    loop {
        match reqs.next().await {
            Some(Ok(TaskRequest::HomeDirectory(info))) => {
                debug!("Received task -> HomeDirectory({:?})", info);

                let resp = match create_home_directory(&info) {
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
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    if cuid != 0 && ceuid != 0 && cgid != 0 && cegid != 0 {
        eprintln!("Refusing to run - this process *MUST* operate as root.");
        std::process::exit(1);
    }

    env_logger::init();

    let unixd_path = Path::new("/etc/kanidm/unixd");
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

    let task_sock_path = cfg.task_sock_path.as_str();
    debug!("Attempting to use {} ...", task_sock_path);

    let server = async move {
        loop {
            info!("Attempting to connect to kanidm_unixd ...");
            // Try to connect to the daemon.
            match UnixStream::connect(task_sock_path).await {
                // Did we connect?
                Ok(stream) => {
                    info!("Found kanidm_unixd, waiting for tasks ...");
                    // Yep! Now let the main handler do it's job.
                    // If it returns (dc, etc, then we loop and try again).
                    handle_tasks(stream).await;
                }
                Err(_e) => {
                    error!("Unable to find kanidm_unixd, sleeping ...");
                    // Back off.
                    time::sleep(Duration::from_millis(5000)).await;
                }
            }
        }
    };

    server.await;
}
