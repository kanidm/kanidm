use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AuditSource {
    Internal,
    Https(IpAddr),
    Ldaps(IpAddr),
}

impl From<Source> for AuditSource {
    fn from(value: Source) -> Self {
        match value {
            Source::Internal => AuditSource::Internal,
            Source::Https(ip) => AuditSource::Https(ip),
            Source::Ldaps(ip) => AuditSource::Ldaps(ip),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    AuthenticationDenied {
        source: AuditSource,
        uuid: Uuid,
        spn: String,
        #[serde(with = "time::serde::timestamp")]
        time: OffsetDateTime,
    },
}
