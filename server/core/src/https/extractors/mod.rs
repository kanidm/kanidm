use axum::{
    async_trait,
    extract::connect_info::{ConnectInfo, Connected},
    extract::FromRequestParts,
    http::{
        header::HeaderName, header::AUTHORIZATION as AUTHORISATION, request::Parts, StatusCode,
    },
    RequestPartsExt,
};

use axum_extra::extract::cookie::CookieJar;

use kanidm_proto::constants::X_FORWARDED_FOR;
use kanidm_proto::internal::COOKIE_BEARER_TOKEN;
use kanidmd_lib::prelude::{ClientAuthInfo, ClientCertInfo, Source};
// Re-export
pub use kanidmd_lib::idm::server::DomainInfoRead;

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

    // Need to skip all to prevent leaking tokens to logs.
    #[instrument(level = "debug", skip_all)]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let ConnectInfo(ClientConnInfo {
            connection_addr,
            client_addr,
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

        let trust_x_forward_for = state
            .trust_x_forward_for_ips
            .as_ref()
            .map(|range| range.contains(&connection_addr.ip()))
            .unwrap_or_default();

        let ip_addr = if trust_x_forward_for {
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
                client_addr.ip()
            }
        } else {
            // This can either be the client_addr == connection_addr if there are
            // no ip address trust sources, or this is the value as reported by
            // proxy protocol header. If the proxy protocol header is used, then
            // trust_x_forward_for can never have been true so we catch here.
            client_addr.ip()
        };

        Ok(TrustedClientIp(ip_addr))
    }
}

pub struct VerifiedClientInformation(pub ClientAuthInfo);

#[async_trait]
impl FromRequestParts<ServerState> for VerifiedClientInformation {
    type Rejection = (StatusCode, &'static str);

    // Need to skip all to prevent leaking tokens to logs.
    #[instrument(level = "debug", skip_all)]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let ConnectInfo(ClientConnInfo {
            connection_addr,
            client_addr,
            client_cert,
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

        let trust_x_forward_for = state
            .trust_x_forward_for_ips
            .as_ref()
            .map(|range| range.contains(&connection_addr.ip()))
            .unwrap_or_default();

        let ip_addr = if trust_x_forward_for {
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
                client_addr.ip()
            }
        } else {
            client_addr.ip()
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
                    if let Ok(jwsc) = JwsCompact::from_str(authz_data) {
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
            // Only if there are no credentials in bearer, do we examine cookies.
            let jar = CookieJar::from_headers(&parts.headers);

            let value: Option<&str> = jar.get(COOKIE_BEARER_TOKEN).map(|c| c.value());

            let maybe_bearer = value.and_then(|authz_data| JwsCompact::from_str(authz_data).ok());

            (None, maybe_bearer)
        };

        Ok(VerifiedClientInformation(ClientAuthInfo {
            source: Source::Https(ip_addr),
            bearer_token,
            basic_authz,
            client_cert,
        }))
    }
}

pub struct DomainInfo(pub DomainInfoRead);

#[async_trait]
impl FromRequestParts<ServerState> for DomainInfo {
    type Rejection = (StatusCode, &'static str);

    // Need to skip all to prevent leaking tokens to logs.
    #[instrument(level = "debug", skip_all)]
    async fn from_request_parts(
        _parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        Ok(DomainInfo(state.qe_r_ref.domain_info_read()))
    }
}

#[derive(Debug, Clone)]
pub struct ClientConnInfo {
    /// This is the address that is *connected* to Kanidm right now
    /// for this operation.
    #[allow(dead_code)]
    pub connection_addr: SocketAddr,
    /// This is the client address as reported by a remote IP source
    /// such as x-forward-for or the PROXY protocol header
    pub client_addr: SocketAddr,
    // Only set if the certificate is VALID
    pub client_cert: Option<ClientCertInfo>,
}

// This is the normal way that our extractors get the ip info
impl Connected<ClientConnInfo> for ClientConnInfo {
    fn connect_info(target: ClientConnInfo) -> Self {
        target
    }
}

// This is only used for plaintext http - in other words, integration tests only.
impl Connected<SocketAddr> for ClientConnInfo {
    fn connect_info(connection_addr: SocketAddr) -> Self {
        ClientConnInfo {
            client_addr: connection_addr,
            connection_addr,
            client_cert: None,
        }
    }
}
