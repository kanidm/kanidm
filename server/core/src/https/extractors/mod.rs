use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{header::HeaderName, request::Parts, StatusCode},
    RequestPartsExt,
};

use std::net::{IpAddr, SocketAddr};

use crate::https::ServerState;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

pub struct TrustedClientIp(pub IpAddr);

#[async_trait]
impl FromRequestParts<ServerState> for TrustedClientIp {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        if state.trust_x_forward_for {
            if let Some(x_forward_for) = parts.headers.get(X_FORWARDED_FOR) {
                // X forward for may be comma seperate.
                let first = x_forward_for
                    .to_str()
                    .map(|s|
                        // Split on an optional comma, return the first result.
                        s.split_once(',')
                            .map(|r| r.0)
                            .unwrap_or(s))
                    .map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            "X-Forwarded-For contains invalid data",
                        )
                    })?;

                first.parse::<IpAddr>().map(TrustedClientIp).map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        "X-Forwarded-For contains invalid ip addr",
                    )
                })
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    "client ipaddr can not be determined",
                ))
            }
        } else {
            let ConnectInfo(addr) =
                parts
                    .extract::<ConnectInfo<SocketAddr>>()
                    .await
                    .map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            "connect info contains invalid ip addr",
                        )
                    })?;

            Ok(TrustedClientIp(addr.ip()))
        }
    }
}
