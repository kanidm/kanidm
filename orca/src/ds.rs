use crate::data::*;
use crate::ldap::{LdapClient, LdapSchema};
use crate::profile::DsConfig;
use crate::{TargetServer, TargetServerBuilder};
use ldap3_server::proto::*;
use std::time::{Duration, Instant};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug)]
pub struct DirectoryServer {
    ldap: LdapClient,
    dm_pw: String,
}

impl DirectoryServer {
    fn construct(uri: String, dm_pw: String,
        basedn: String,
    ) -> Result<Self, ()> {
        let ldap = LdapClient::new(uri, basedn, LdapSchema::Rfc2307bis)?;

        Ok(DirectoryServer { ldap, dm_pw })
    }

    pub fn build(uri: String, dm_pw: String,
        basedn: String,
    ) -> Result<TargetServer, ()> {
        Self::construct(uri, dm_pw, basedn).map(TargetServer::DirSrv)
    }

    pub fn new(lconfig: &DsConfig) -> Result<TargetServer, ()> {
        Self::construct(lconfig.uri.clone(), lconfig.dm_pw.clone(), lconfig.base_dn.clone()).map(TargetServer::DirSrv)
    }

    pub fn info(&self) -> String {
        format!("Directory Server Connection: {}", self.ldap.uri)
    }

    pub fn builder(&self) -> TargetServerBuilder {
        TargetServerBuilder::DirSrv(
            self.ldap.uri.clone(),
            self.dm_pw.clone(),
            self.ldap.basedn.clone(),
     )
    }

    pub async fn open_admin_connection(&self) -> Result<(), ()> {
        self.ldap.open_dm_connection(&self.dm_pw).await
    }

    pub async fn setup_admin_delete_uuids(&self, targets: &[Uuid]) -> Result<(), ()> {
        // We might hit admin limits depending on the dataset size, so we probably
        // need to do this iteratively eventually. Or just change the limits ...

        let filter = LdapFilter::Or(
                targets.iter()
                    .map(|u| LdapFilter::Equality("uid".to_string(), u.to_string()))
                    .collect());

        let res = self.ldap.search(filter).await?;

        for ent in res.iter() {
            self.ldap.delete(ent.dn.clone()).await?;
        }
        Ok(())
    }

    pub async fn setup_admin_precreate_entities(
        &self,
        targets: &HashSet<Uuid>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        // Check if ou=people and ou=group exist
        let res = self.ldap.search(
            LdapFilter::Equality("ou".to_string(), "people".to_string())).await?;

        if res.is_empty() {
            // Doesn't exist
            info!("Creating ou=people");
        }

        let res = self.ldap.search(
            LdapFilter::Equality("ou".to_string(), "groups".to_string())).await?;

        if res.is_empty() {
            // Doesn't exist
            info!("Creating ou=groups");
        }

        // Now go and create the rest.

        // We stick ACI's on the rootdse, so we can clear them and reset them easier.

        unimplemented!();
    }

    pub async fn setup_access_controls(
        &self,
        access: &HashMap<Uuid, Vec<EntityType>>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        unimplemented!();
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
