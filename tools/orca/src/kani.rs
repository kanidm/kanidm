use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder, StatusCode};
use kanidm_proto::v1::*;
use uuid::Uuid;

use crate::data::*;
use crate::ldap::{LdapClient, LdapSchema};
use crate::profile::{KaniHttpConfig, KaniLdapConfig};
use crate::{TargetServer, TargetServerBuilder};

#[derive(Debug)]
pub struct KaniHttpServer {
    uri: String,
    admin_pw: String,
    client: KanidmClient,
}

#[derive(Debug)]
pub struct KaniLdapServer {
    http: KaniHttpServer,
    ldap: LdapClient,
}

impl KaniHttpServer {
    fn construct(uri: String, admin_pw: String) -> Result<Self, ()> {
        let client = KanidmClientBuilder::new()
            .address(uri.clone())
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| {
                error!("Unable to create kanidm client {:?}", e);
            })?;

        Ok(KaniHttpServer {
            uri,
            admin_pw,
            client,
        })
    }

    pub fn build(uri: String, admin_pw: String) -> Result<TargetServer, ()> {
        Self::construct(uri, admin_pw).map(TargetServer::Kanidm)
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(khconfig: &KaniHttpConfig) -> Result<TargetServer, ()> {
        Self::construct(khconfig.uri.clone(), khconfig.admin_pw.clone()).map(TargetServer::Kanidm)
    }

    pub fn info(&self) -> String {
        format!("Kanidm HTTP Connection: {}", self.uri)
    }

    pub fn builder(&self) -> TargetServerBuilder {
        TargetServerBuilder::Kanidm(self.uri.clone(), self.admin_pw.clone())
    }

    // open the admin internal connection
    pub async fn open_admin_connection(&self) -> Result<(), ()> {
        self.client
            .auth_simple_password("admin", &self.admin_pw)
            .await
            .map_err(|e| {
                error!("Unable to authenticate -> {:?}", e);
            })?;
        // For admin to work, we need idm permissions.
        // NOT RECOMMENDED IN PRODUCTION.
        self.client
            .idm_group_add_members("idm_admins", &["admin"])
            .await
            .map(|_| ())
            .map_err(|e| {
                error!("Unable to extend admin permissions (idm) -> {:?}", e);
            })
    }

    pub async fn setup_admin_delete_uuids(&self, targets: &[Uuid]) -> Result<(), ()> {
        // Build the filter.
        let inner: Vec<Filter> = targets
            .iter()
            .map(|u| Filter::Eq("name".to_string(), format!("{}", u)))
            .collect();

        let filter = Filter::Or(inner);

        // Submit it.
        self.client.delete(filter).await.map(|_| ()).or_else(|e| {
            error!("Error during delete -> {:?}", e);
            Ok(())
        })
    }

    pub async fn setup_admin_precreate_entities(
        &self,
        targets: &HashSet<Uuid>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        // Create all the accounts and groups
        for u in targets {
            let e = all_entities.get(u).unwrap();
            match e {
                Entity::Account(a) => {
                    self.client
                        .idm_person_account_create(&a.name, &a.display_name)
                        .await
                        .map(|_| ())
                        .or_else(|e| {
                            match e {
                                ClientError::Http(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Some(OperationError::Plugin(PluginError::AttrUnique(_))),
                                    _,
                                ) => {
                                    // Ignore.
                                    debug!("Account already exists ...");
                                    Ok(())
                                }
                                _ => {
                                    error!("Error creating account -> {:?}", e);
                                    Err(())
                                }
                            }
                        })?;

                    // Now set the account password
                    self.client
                        .idm_person_account_primary_credential_set_password(&a.name, &a.password)
                        .await
                        .map(|_| ())
                        .map_err(|e| {
                            error!("Unable to set password for {}: {:?}", a.name, e);
                        })?;

                    // For ldap tests, we need to make these posix accounts.
                    self.client
                        .idm_person_account_unix_extend(&a.name, None, None)
                        .await
                        .map(|_| ())
                        .map_err(|e| {
                            error!("Unable to set unix attributes for {}: {:?}", a.name, e);
                        })?;

                    self.client
                        .idm_person_account_unix_cred_put(&a.name, &a.password)
                        .await
                        .map(|_| ())
                        .map_err(|e| {
                            error!("Unable to set unix password for {}: {:?}", a.name, e);
                        })?;
                }
                Entity::Group(g) => {
                    self.client
                        .idm_group_create(&g.name)
                        .await
                        .map(|_| ())
                        .or_else(|e| {
                            match e {
                                ClientError::Http(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Some(OperationError::Plugin(PluginError::AttrUnique(_))),
                                    _,
                                ) => {
                                    // Ignore.
                                    debug!("Group already exists ...");
                                    Ok(())
                                }
                                _ => {
                                    error!("Error creating group -> {:?}", e);
                                    Err(())
                                }
                            }
                        })?;
                }
            }
        }

        // Then add the members to the groups.
        for g in targets.iter().filter_map(|u| {
            let e = all_entities.get(u).unwrap();
            match e {
                Entity::Group(g) => Some(g),
                _ => None,
            }
        }) {
            let m: Vec<_> = g
                .members
                .iter()
                .map(|id| all_entities.get(id).unwrap().get_name())
                .collect();
            self.client
                .idm_group_set_members(&g.name, m.as_slice())
                .await
                .map(|_| ())
                .or_else(|e| {
                    error!("Error setting group members -> {:?}", e);
                    Ok(())
                })?;
        }

        Ok(())
    }

    pub async fn setup_access_controls(
        &self,
        access: &HashMap<Uuid, Vec<EntityType>>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        // To make this somewhat efficient, we fold each access req to "need group" or "need user"
        // access.
        debug!("setup_access_controls");

        for (id, list) in access.iter() {
            // get the users name.
            let account = all_entities.get(id).unwrap();

            let need_account = list
                .iter()
                .filter(|v| matches!(v, EntityType::Account(_)))
                .count()
                == 0;
            let need_group = list
                .iter()
                .filter(|v| matches!(v, EntityType::Group(_)))
                .count()
                == 0;

            if need_account {
                self.client
                    .idm_group_add_members("idm_account_manage_priv", &[account.get_name()])
                    .await
                    .map(|_| ())
                    .or_else(|e| {
                        error!("Error setting group members -> {:?}", e);
                        Ok(())
                    })?;

                self.client
                    .idm_group_add_members("idm_hp_account_manage_priv", &[account.get_name()])
                    .await
                    .map(|_| ())
                    .or_else(|e| {
                        error!("Error setting group members -> {:?}", e);
                        Ok(())
                    })?;
            }
            if need_group {
                self.client
                    .idm_group_add_members("idm_group_manage_priv", &[account.get_name()])
                    .await
                    .map(|_| ())
                    .or_else(|e| {
                        error!("Error setting group members -> {:?}", e);
                        Ok(())
                    })?;

                self.client
                    .idm_group_add_members("idm_hp_group_manage_priv", &[account.get_name()])
                    .await
                    .map(|_| ())
                    .or_else(|e| {
                        error!("Error setting group members -> {:?}", e);
                        Ok(())
                    })?;
            }
        }
        Ok(())
    }

    pub async fn open_user_connection(
        &self,
        test_start: Instant,
        name: &str,
        pw: &str,
    ) -> Result<(Duration, Duration), ()> {
        let start = Instant::now();
        self.client
            .auth_simple_password(name, pw)
            .await
            .map_err(|e| {
                error!("Unable to authenticate -> {:?}", e);
            })
            .map(|_| {
                let end = Instant::now();
                let diff = end.duration_since(start);
                let rel_diff = start.duration_since(test_start);
                (rel_diff, diff)
            })
    }

    pub async fn close_connection(&self) {
        assert!(self
            .client
            .logout()
            .await
            .map_err(|e| error!("close_connection {:?}", e))
            .is_ok());
    }

    pub async fn search(
        &self,
        test_start: Instant,
        ids: &[String],
    ) -> Result<(Duration, Duration, usize), ()> {
        // Create the filter
        let inner: Vec<_> = ids
            .iter()
            .map(|n| Filter::Eq("name".to_string(), n.to_string()))
            .collect();
        let filter = Filter::Or(inner);

        let start = Instant::now();
        let l = self
            .client
            .search(filter)
            .await
            .map(|r| r.len())
            .map_err(|e| {
                error!("{:?}", e);
            })?;

        let end = Instant::now();
        let diff = end.duration_since(start);
        let rel_diff = start.duration_since(test_start);

        Ok((rel_diff, diff, l))
    }
}

impl KaniLdapServer {
    fn construct(
        uri: String,
        admin_pw: String,
        ldap_uri: String,
        basedn: String,
    ) -> Result<Box<Self>, ()> {
        let http = KaniHttpServer::construct(uri, admin_pw)?;
        let ldap = LdapClient::new(ldap_uri, basedn, LdapSchema::Kanidm)?;

        Ok(Box::new(KaniLdapServer { http, ldap }))
    }

    pub fn build(
        uri: String,
        admin_pw: String,
        ldap_uri: String,
        basedn: String,
    ) -> Result<TargetServer, ()> {
        Self::construct(uri, admin_pw, ldap_uri, basedn).map(TargetServer::KanidmLdap)
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(klconfig: &KaniLdapConfig) -> Result<TargetServer, ()> {
        Self::construct(
            klconfig.uri.clone(),
            klconfig.admin_pw.clone(),
            klconfig.ldap_uri.clone(),
            klconfig.base_dn.clone(),
        )
        .map(TargetServer::KanidmLdap)
    }

    pub fn info(&self) -> String {
        format!(
            "Kanidm LDAP Connection: {} {}",
            self.ldap.uri, self.ldap.basedn
        )
    }

    pub fn builder(&self) -> TargetServerBuilder {
        TargetServerBuilder::KanidmLdap(
            self.http.uri.clone(),
            self.http.admin_pw.clone(),
            self.ldap.uri.clone(),
            self.ldap.basedn.clone(),
        )
    }

    pub async fn open_admin_connection(&self) -> Result<(), ()> {
        self.http.open_admin_connection().await
    }

    pub async fn setup_admin_delete_uuids(&self, targets: &[Uuid]) -> Result<(), ()> {
        self.http.setup_admin_delete_uuids(targets).await
    }

    pub async fn setup_admin_precreate_entities(
        &self,
        targets: &HashSet<Uuid>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        self.http
            .setup_admin_precreate_entities(targets, all_entities)
            .await
    }

    pub async fn setup_access_controls(
        &self,
        access: &HashMap<Uuid, Vec<EntityType>>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        self.http.setup_access_controls(access, all_entities).await
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
