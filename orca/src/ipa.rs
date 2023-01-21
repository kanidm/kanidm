use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
// use ldap3_proto::proto::*;
use uuid::Uuid;

use crate::data::*;
use crate::ldap::{LdapClient, LdapSchema};
use crate::profile::IpaConfig;
use crate::{TargetServer, TargetServerBuilder};


#[derive(Debug)]
pub struct IpaServer {
    ldap: LdapClient,
    realm: String,
    admin_pw: String,
}

impl IpaServer {
    fn construct(uri: String, realm: String, admin_pw: String) -> Result<Self, ()> {
        // explode the realm to basedn.
        //   dev.kanidm.com
        //   dc=dev,dc=kanidm,dc=com
        let basedn = format!("dc={}", realm.replace('.', ",dc="));

        let ldap = LdapClient::new(uri, basedn, LdapSchema::Rfc2307bis)?;

        Ok(IpaServer { ldap, realm, admin_pw })
    }

    pub fn build(uri: String, realm: String, admin_pw: String) -> Result<TargetServer, ()> {
        Self::construct(uri, realm, admin_pw).map(TargetServer::Ipa)
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(lconfig: &IpaConfig) -> Result<TargetServer, ()> {
        Self::construct(
            lconfig.uri.clone(),
            lconfig.realm.clone(),
            lconfig.admin_pw.clone(),
        )
        .map(TargetServer::Ipa)
    }

    pub fn info(&self) -> String {
        format!("Ipa Server Connection: {} @ {}", self.realm, self.ldap.uri)
    }

    pub fn builder(&self) -> TargetServerBuilder {
        TargetServerBuilder::Ipa(
            self.ldap.uri.clone(),
            self.realm.clone(),
            self.admin_pw.clone(),
        )
    }

    pub async fn open_admin_connection(&self) -> Result<(), ()> {
        self.ldap.open_ipa_admin_connection(&self.admin_pw).await
    }

    pub async fn setup_admin_delete_uuids(&self, _targets: &[Uuid]) -> Result<(), ()> {
        todo!();
    }

    pub async fn setup_admin_precreate_entities(
        &self,
        _targets: &HashSet<Uuid>,
        _all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        todo!();
    }

    pub async fn setup_access_controls(
        &self,
        _access: &HashMap<Uuid, Vec<EntityType>>,
        _all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        todo!();
    }

    pub async fn open_user_connection(
        &self,
        test_start: Instant,
        name: &str,
        pw: &str,
    ) -> Result<(Duration, Duration), ()> {
        self.ldap.open_user_connection(test_start, name, pw).await
    }

    pub async fn close_connection(&self) {
        self.ldap.close_connection().await;
    }

    pub async fn search(
        &self,
        test_start: Instant,
        ids: &[String],
    ) -> Result<(Duration, Duration, usize), ()> {
        self.ldap.search_name(test_start, ids).await
    }
}
