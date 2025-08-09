use crate::https::ServerState;
use axum::{
    async_trait,
    extract::{connect_info::Connected, FromRequestParts},
    http::{header::AUTHORIZATION as AUTHORISATION, request::Parts, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use compact_jwt::JwsCompact;
use kanidm_proto::internal::COOKIE_BEARER_TOKEN;
use kanidmd_lib::prelude::{ClientAuthInfo, ClientCertInfo, Source};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::fmt;

// Re-export
pub use kanidmd_lib::idm::server::DomainInfoRead;

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
        let ClientConnInfo {
            connection_addr: _,
            client_ip_addr,
            client_cert,
        } = parts.extensions.remove::<ClientConnInfo>().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "request info contains invalid data",
        ))?;

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

        let mut client_auth_info = ClientAuthInfo::new(
            Source::Https(client_ip_addr),
            client_cert,
            bearer_token,
            basic_authz,
        );

        // now, we want to update the client auth info with the sessions user-auth-token
        // if any. We ignore errors here as the auth info MAY NOT be a valid token
        // and so in that case no prevalidation will occur.
        let _ = state
            .qe_r_ref
            .pre_validate_client_auth_info(&mut client_auth_info)
            .await;

        Ok(VerifiedClientInformation(client_auth_info))
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
pub enum ConnectionAddress {
    Unix,
    Tcp(SocketAddr)
}

impl fmt::Display for ConnectionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionAddress::Unix => write!(f, "unix://"),
            ConnectionAddress::Tcp(socket_address) => write!(f, "tcp://{socket_address}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientConnInfo {
    /// This is the address that is *connected* to Kanidm right now
    /// for this operation.
    #[allow(dead_code)]
    pub connection_addr: ConnectionAddress,
    /// This is the client address as reported by a remote IP source
    /// such as x-forward-for or the PROXY protocol header
    pub client_ip_addr: IpAddr,
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
            connection_addr: ConnectionAddress::Tcp(connection_addr),
            client_ip_addr: connection_addr.ip(),
            client_cert: None,
        }
    }
}
