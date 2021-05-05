use crate::data::*;
use crate::profile::KaniHttpConfig;
use crate::{TargetServer, TargetServerBuilder};
use kanidm_client::{
    asynchronous::KanidmAsyncClient, ClientError, KanidmClientBuilder, StatusCode,
};
use kanidm_proto::v1::*;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug)]
pub struct KaniHttpServer {
    uri: String,
    admin_pw: String,
    client: KanidmAsyncClient,
}

impl KaniHttpServer {
    pub fn build(uri: String, admin_pw: String) -> Result<TargetServer, ()> {
        let client = KanidmClientBuilder::new()
            .address(uri.clone())
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build_async()
            .map_err(|e| {
                error!("Unable to create kanidm client {:?}", e);
            })?;

        Ok(TargetServer::Kanidm(KaniHttpServer {
            uri,
            admin_pw,
            client,
        }))
    }

    pub fn new(khconfig: &KaniHttpConfig) -> Result<TargetServer, ()> {
        Self::build(khconfig.uri.clone(), khconfig.admin_pw.clone())
    }

    pub fn info(&self) -> String {
        format!("Kanidm HTTP Connection: {}", self.uri)
    }

    pub fn builder(&self) -> TargetServerBuilder {
        TargetServerBuilder::Kanidm(self.uri.clone(), self.admin_pw.clone())
    }

    pub async fn open_user_connection(&self, name: &str, pw: &str) -> Result<(), ()> {
        self.client
            .auth_simple_password(name, pw)
            .await
            .map_err(|e| {
                error!("Unable to authenticate -> {:?}", e);
            })
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
                error!("Unable to extend admin permissions -> {:?}", e);
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
                        .idm_account_create(&a.name, &a.display_name)
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
                        .idm_account_primary_credential_set_password(&a.name, &a.password)
                        .await
                        .map(|_| ())
                        .map_err(|e| {
                            error!("Unable to set password for {}", a.name);
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
        // To make this somewhat effecient, we fold each access req to "need group" or "need user"
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
        let filter = Filter::And(inner);

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
