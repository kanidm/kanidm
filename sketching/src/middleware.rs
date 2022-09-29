use tide::{self, Middleware, Next, Request};
use tracing::{self, instrument};

use crate::{request_error, request_info, request_warn, security_info, *};

#[derive(Default)]
pub struct TreeMiddleware {}

// impl Default for TreeMiddleware {
//     fn default() -> Self {
//         TreeMiddleware {}
//     }
// }

impl TreeMiddleware {
    #[instrument(name = "tide-request", skip(self, req, next))]
    async fn log<'a, State: Clone + Send + Sync + 'static>(
        &'a self,
        mut req: Request<State>,
        next: Next<'a, State>,
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
        self.log(req, next).await
    }
}
