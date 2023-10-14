use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{header::HeaderName, request::Parts, StatusCode},
    RequestPartsExt,
};
use kanidm_proto::constants::X_FORWARDED_FOR;

use std::net::{IpAddr, SocketAddr};

use crate::https::ServerState;

#[allow(clippy::declare_interior_mutable_const)]
const X_FORWARDED_FOR_HEADER: HeaderName = HeaderName::from_static(X_FORWARDED_FOR);

pub struct TrustedClientIp(pub IpAddr);

#[async_trait]
impl FromRequestParts<ServerState> for TrustedClientIp {
    type Rejection = (StatusCode, &'static str);

    #[instrument(level = "debug", skip(state))]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        if state.trust_x_forward_for {
            if let Some(x_forward_for) = parts.headers.get(X_FORWARDED_FOR_HEADER) {
                // X forward for may be comma separate.
                let first = x_forward_for
                    .to_str()
                    .map(|s|
                        // Split on an optional comma, return the first result.
                        s.split(',').next().unwrap_or(s))
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
                let ConnectInfo(addr) =
                    parts
                        .extract::<ConnectInfo<SocketAddr>>()
                        .await
                        .map_err(|_| {
                            error!("Connect info contains invalid IP address");
                            (
                                StatusCode::BAD_REQUEST,
                                "connect info contains invalid IP address",
                            )
                        })?;

                Ok(TrustedClientIp(addr.ip()))
            }
        } else {
            let ConnectInfo(addr) =
                parts
                    .extract::<ConnectInfo<SocketAddr>>()
                    .await
                    .map_err(|_| {
                        error!("Connect info contains invalid IP address");
                        (
                            StatusCode::BAD_REQUEST,
                            "connect info contains invalid IP address",
                        )
                    })?;

            Ok(TrustedClientIp(addr.ip()))
        }
    }
}
