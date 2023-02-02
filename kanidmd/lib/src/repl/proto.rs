use crate::prelude::*;

pub struct ReplEntry {}

pub struct ReplRefreshContext {
    pub domain_version: DomainVersion,
    pub domain_uuid: Uuid,
    pub schema_entries: Vec<ReplEntry>,
    pub meta_entries: Vec<ReplEntry>,
    pub entries: Vec<ReplEntry>,
}
