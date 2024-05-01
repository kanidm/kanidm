use axum::{
    async_trait,
    extract::{
        connect_info::{ConnectInfo, Connected},
        FromRequest, FromRequestParts,
    },
    http::{
        header::{HeaderName, AUTHORIZATION as AUTHORISATION},
        request::Parts,
        StatusCode,
    },
    RequestPartsExt,
};

use kanidm_proto::constants::X_FORWARDED_FOR;
use kanidmd_lib::prelude::{ClientAuthInfo, ClientCertInfo, Source};
use tokio::net::TcpStream;

use compact_jwt::JwsCompact;
use std::str::FromStr;

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
        let ConnectInfo(ClientConnInfo {
            addr,
            client_cert: _,
        }) = parts
            .extract::<ConnectInfo<ClientConnInfo>>()
            .await
            .map_err(|_| {
                error!("Connect info contains invalid data");
                (
                    StatusCode::BAD_REQUEST,
                    "connect info contains invalid data",
                )
            })?;

        let ip_addr = if state.trust_x_forward_for {
            if let Some(x_forward_for) = parts.headers.get(X_FORWARDED_FOR_HEADER) {
                // X forward for may be comma separated.
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

                first.parse::<IpAddr>().map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        "X-Forwarded-For contains invalid ip addr",
                    )
                })?
            } else {
                addr.ip()
            }
        } else {
            addr.ip()
        };

        Ok(TrustedClientIp(ip_addr))
    }
}

pub struct VerifiedClientInformation(pub ClientAuthInfo);

#[async_trait]
impl FromRequestParts<ServerState> for VerifiedClientInformation {
    type Rejection = &'static str;

    #[instrument(level = "debug", skip(state))]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let ConnectInfo(ClientConnInfo { addr, client_cert }) = parts
            .extract::<ConnectInfo<ClientConnInfo>>()
            .await
            .map_err(|_| {
                error!("Connect info contains invalid data");
                // (
                // StatusCode::BAD_REQUEST,
                "connect info contains invalid data"
                // ,
                // )
            })?;

        let ip_addr = if state.trust_x_forward_for {
            if let Some(x_forward_for) = parts.headers.get(X_FORWARDED_FOR_HEADER) {
                // X forward for may be comma separated.
                let first = x_forward_for
                    .to_str()
                    .map(|s|
                        // Split on an optional comma, return the first result.
                        s.split(',').next().unwrap_or(s))
                    .map_err(|_| {
                        // (
                        // StatusCode::BAD_REQUEST,
                        "X-Forwarded-For contains invalid data"
                        // ,
                        // )
                    })?;

                first.parse::<IpAddr>().map_err(|_| {
                    // (
                    // StatusCode::BAD_REQUEST,
                    "X-Forwarded-For contains invalid ip addr"
                    // ,
                    // )
                })?
            } else {
                addr.ip()
            }
        } else {
            addr.ip()
        };

        let (basic_authz, bearer_token) = if let Some(header) = parts.headers.get(AUTHORISATION) {
            if let Some((authz_type, authz_data)) = header
                .to_str()
                .map_err(|err| {
                    warn!(?err, "Invalid authz header, ignoring");
                })
                .ok()
                .and_then(|s| s.split_once(' '))
            {
                let authz_type = authz_type.to_lowercase();

                if authz_type == "basic" {
                    (Some(authz_data.to_string()), None)
                } else if authz_type == "bearer" {
                    if let Some(jwsc) = JwsCompact::from_str(authz_data).ok() {
                        (None, Some(jwsc))
                    } else {
                        warn!("bearer jws invalid");
                        (None, None)
                    }
                } else {
                    warn!("authorisation header invalid, ignoring");
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Ok(VerifiedClientInformation(ClientAuthInfo {
            source: Source::Https(ip_addr),
            bearer_token,
            basic_authz,
            client_cert,
        }))
    }
}

#[async_trait]
impl FromRequest<ServerState, axum::body::Body>
    for axum::Form<kanidm_proto::oauth2::AccessTokenRequest>
{
    type Rejection = &'static str;

    // #[instrument(level = "debug", skip(state))]
    async fn from_request(
        _request: axum::extract::Request,
        _state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        todo!()
    }
}

#[async_trait]
impl FromRequest<ServerState, axum::body::Body> for VerifiedClientInformation {
    type Rejection = &'static str;

    #[instrument(level = "debug", skip(state))]
    async fn from_request(
        request: axum::extract::Request,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let (parts, _body) = request.into_parts();
        let ConnectInfo(ClientConnInfo { addr, client_cert }) = parts
            .extract::<ConnectInfo<ClientConnInfo>>()
            .await
            .map_err(|_| {
                error!("Connect info contains invalid data");
                // (
                // StatusCode::BAD_REQUEST,
                "connect info contains invalid data"
                // ,
                // )
            })?;

        let ip_addr = if state.trust_x_forward_for {
            if let Some(x_forward_for) = parts.headers.get(X_FORWARDED_FOR_HEADER) {
                // X forward for may be comma separated.
                let first = x_forward_for
                    .to_str()
                    .map(|s|
                        // Split on an optional comma, return the first result.
                        s.split(',').next().unwrap_or(s))
                    .map_err(|_| {
                        // (
                        // StatusCode::BAD_REQUEST,
                        "X-Forwarded-For contains invalid data"
                        // ,
                        // )
                    })?;

                first.parse::<IpAddr>().map_err(|_| {
                    // (
                    // StatusCode::BAD_REQUEST,
                    "X-Forwarded-For contains invalid ip addr"
                    // ,
                    // )
                })?
            } else {
                addr.ip()
            }
        } else {
            addr.ip()
        };

        let bearer_token = if let Some(header) = parts.headers.get(AUTHORISATION) {
            header
                .to_str()
                .map_err(|err| {
                    warn!(?err, "Invalid bearer token, ignoring");
                })
                .ok()
                .and_then(|s| s.split_once(' '))
                .map(|(_, s)| s.to_string())
                .or_else(|| {
                    warn!("bearer token format invalid, ignoring");
                    None
                })
        } else {
            None
        };

        Ok(VerifiedClientInformation(ClientAuthInfo {
            source: Source::Https(ip_addr),
            client_cert,
            bearer_token: None,
            // bearer_token, // TODO
            basic_authz: None,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ClientConnInfo {
    pub addr: SocketAddr,
    // Only set if the certificate is VALID
    pub client_cert: Option<ClientCertInfo>,
}

impl Connected<ClientConnInfo> for ClientConnInfo {
    fn connect_info(target: ClientConnInfo) -> Self {
        target
    }
}

impl<'a> Connected<&'a TcpStream> for ClientConnInfo {
    fn connect_info(target: &'a TcpStream) -> Self {
        ClientConnInfo {
            addr: target.peer_addr().expect("Failed to get peer addr"),
            client_cert: None,
        }
    }
}
