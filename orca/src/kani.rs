use crate::profile::KaniHttpConfig;
use crate::data::Entity;
use crate::TargetServer;
use async_trait::async_trait;
use kanidm_proto::v1::*;
use kanidm_client::{asynchronous::KanidmAsyncClient, KanidmClientBuilder, ClientError, StatusCode};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug)]
pub struct KaniHttpServer {
    uri: String,
    admin_pw: String,
    admin_client: KanidmAsyncClient,
}

impl KaniHttpServer {
    pub fn new(khconfig: &KaniHttpConfig) -> Result<Box<dyn TargetServer>, ()> {
        let admin_client = KanidmClientBuilder::new()
            .address(khconfig.uri.clone())
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build_async()
            .map_err(|e| {
                error!("Unable to create kanidm client {:?}", e);
            })?;

        Ok(Box::new(KaniHttpServer {
            uri: khconfig.uri.clone(),
            admin_pw: khconfig.admin_pw.clone(),
            admin_client,
        }))
    }
}

#[async_trait]
impl TargetServer for KaniHttpServer {
    fn info(&self) -> String {
        format!("Kanidm HTTP Connection: {}", self.uri)
    }

    // open the admin internal connection
    async fn open_admin_connection(&mut self) -> Result<(), ()> {
        self.admin_client
            .auth_simple_password("admin", &self.admin_pw)
            .await
            .map_err(|e| {
                error!("Unable to authenticate -> {:?}", e);
            })?;

        // For admin to work, we need idm permissions.
        // NOT RECOMMENDED IN PRODUCTION.

        self.admin_client
            .idm_group_add_members("idm_admins", &["admin"])
            .await
            .map(|_| ())
            .map_err(|e| {
                error!("Unable to extend admin permissions -> {:?}", e);
            })
    }

    async fn setup_admin_delete_uuids(&self, targets: &[Uuid]) -> Result<(), ()> {
        // Build the filter.
        let inner: Vec<Filter> = targets.iter()
            .map(|u| {
                Filter::Eq("name".to_string(), format!("{}", u))
            })
            .collect();

        let filter = Filter::Or(inner);

        // Submit it.
        self.admin_client
            .delete(filter)
            .await
            .map(|_| ())
            .or_else(|e| {
                error!("Error during delete -> {:?}", e);
                Ok(())
            })
    }

    async fn setup_admin_precreate_entities(&self, targets: &[Uuid], all_entities: &HashMap<Uuid, Entity>) -> Result<(), ()> {
        // Create all the accounts and groups
        for u in targets {
            let e = all_entities.get(u).unwrap();
            match e {
                Entity::Account(a) => {
                    self.admin_client
                        .idm_account_create(
                            &a.name,
                            &a.display_name
                        )
                        .await
                        .map(|_| ())
                        .or_else(|e| {
                            match e {
                                ClientError::Http(StatusCode::INTERNAL_SERVER_ERROR, Some(OperationError::Plugin(PluginError::AttrUnique(_))), _) => {
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
                }
                Entity::Group(g) => {
                    self.admin_client
                        .idm_group_create(
                            &g.name
                        )
                        .await
                        .map(|_| ())
                        .or_else(|e| {
                            match e {
                                ClientError::Http(StatusCode::INTERNAL_SERVER_ERROR, Some(OperationError::Plugin(PluginError::AttrUnique(_))), _) => {
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
            }}) {
            let m: Vec<_> = g.members.iter()
                .map(|id| all_entities.get(id).unwrap().get_name()     )
                .collect();
            self.admin_client
                .idm_group_set_members(&g.name, m.as_slice())
                .await
                .map(|_| ())
                .or_else(|e| {
                    error!("Error setting group members -> {:?}", e);
                    Ok(())
                })?;
        }


        // Set passwords on the accounts?


        Ok(())
    }
}
