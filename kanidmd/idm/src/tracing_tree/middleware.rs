use std::path::PathBuf;

use super::subscriber::TreeIo;
use crate::prelude::*;
use tide::{self, Middleware, Next, Request};
use tracing::{self, instrument};

// Modeled after:
// https://docs.rs/tide/0.16.0/src/tide/log/middleware.rs.html#23-96

pub struct TreeMiddleware {
    output: TreeIo,
}

impl TreeMiddleware {
    #[allow(dead_code)]
    pub fn with_stdout() -> Self {
        TreeMiddleware {
            output: TreeIo::Stdout,
        }
    }

    #[allow(dead_code)]
    pub fn with_stderr() -> Self {
        TreeMiddleware {
            output: TreeIo::Stderr,
        }
    }

    #[allow(dead_code)]
    pub fn with_file(path: &str) -> Self {
        TreeMiddleware {
            output: TreeIo::File(PathBuf::from(path)),
        }
    }

    #[instrument(name = "tide-request", skip(self, req, next, output), fields(%output))]
    async fn log<'a, State: Clone + Send + Sync + 'static>(
        &'a self,
        mut req: Request<State>,
        next: Next<'a, State>,
        output: &str,
    ) -> tide::Result {
        struct TreeMiddlewareFinished;

        if req.ext::<TreeMiddlewareFinished>().is_some() {
            return Ok(next.run(req).await);
        }
        req.set_ext(TreeMiddlewareFinished);

        let remote_address = req.remote().unwrap_or("-").to_string();
        let host = req.host().unwrap_or("-").to_string();
        let method = req.method();
        let path = req.url().path().to_string();

        let remote_address = remote_address.as_str();
        let host = host.as_str();
        let method = method.as_ref();
        let path = path.as_str();

        security_info!(
            src = remote_address,
            http.host = host,
            http.method = method,
            path,
            "Request received"
        );

        let response = next.run(req).await;
        let status = response.status();

        if status.is_server_error() {
            if let Some(error) = response.error() {
                request_error!(
                    message = display(error),
                    error_type = error.type_name().unwrap_or("?"),
                    status = format_args!("{} - {}", status as u16, status.canonical_reason()),
                    "Internal error -> Response sent"
                );
            } else {
                request_error!(
                    status = format_args!("{} - {}", status as u16, status.canonical_reason()),
                    "Internal error -> Response sent"
                );
            }
        } else if status.is_client_error() {
            if let Some(error) = response.error() {
                request_warn!(
                    message = display(error),
                    error_type = error.type_name().unwrap_or("?"),
                    status = format_args!("{} - {}", status as u16, status.canonical_reason()),
                    "Client error --> Response sent"
                );
            } else {
                request_warn!(
                    status = format_args!("{} - {}", status as u16, status.canonical_reason()),
                    "Client error --> Response sent"
                );
            }
        } else {
            request_info!(
                status = format_args!("{} - {}", status as u16, status.canonical_reason()),
                "--> Response sent"
            );
        }

        Ok(response)
    }
}

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for TreeMiddleware {
    async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> tide::Result {
        let output = match self.output {
            TreeIo::Stdout => "console stdout",
            TreeIo::Stderr => "console stderr",
            TreeIo::File(ref path) => path.to_str().unwrap_or_else(|| {
                eprintln!("File path isn't UTF-8, cannot write logs to: {:#?}", path);
                std::process::exit(1);
                // warn!(
                //     "File path isn't UTF-8, logging to stderr instead: {:#?}",
                //     path
                // );
                // "console stderr"
            }),
        };

        self.log(req, next, output).await
    }
}
