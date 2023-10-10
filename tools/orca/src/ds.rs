use hashbrown::{HashMap, HashSet};
use kanidm_proto::constants::{ATTR_UID, LDAP_ATTR_DISPLAY_NAME, LDAP_ATTR_CN, LDAP_ATTR_OBJECTCLASS, LDAP_ATTR_OU, LDAP_ATTR_GROUPS};
use std::time::{Duration, Instant};

use ldap3_proto::proto::*;
use uuid::Uuid;

use crate::data::*;
use crate::ldap::{LdapClient, LdapSchema};
use crate::profile::DsConfig;
use crate::{TargetServer, TargetServerBuilder};

#[derive(Debug)]
pub struct DirectoryServer {
    ldap: LdapClient,
    dm_pw: String,
}

impl DirectoryServer {
    fn construct(uri: String, dm_pw: String, basedn: String) -> Result<Self, ()> {
        let ldap = LdapClient::new(uri, basedn, LdapSchema::Rfc2307bis)?;

        Ok(DirectoryServer { ldap, dm_pw })
    }

    pub fn build(uri: String, dm_pw: String, basedn: String) -> Result<TargetServer, ()> {
        Self::construct(uri, dm_pw, basedn).map(TargetServer::DirSrv)
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(lconfig: &DsConfig) -> Result<TargetServer, ()> {
        Self::construct(
            lconfig.uri.clone(),
            lconfig.dm_pw.clone(),
            lconfig.base_dn.clone(),
        )
        .map(TargetServer::DirSrv)
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
            targets
                .iter()
                .map(|u| LdapFilter::Equality(LDAP_ATTR_CN.to_string(), u.to_string()))
                .collect(),
        );

        print!("(|");
        for u in targets.iter() {
            print!("(cn={})", u);
        }
        println!(")");

        let res = self.ldap.search(filter).await?;

        for ent in res.iter() {
            debug!("Deleting ... {}", ent.dn);
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
        let res = self
            .ldap
            .search(LdapFilter::Equality(LDAP_ATTR_OU.to_string(), "people".to_string()))
            .await?;

        if res.is_empty() {
            // Doesn't exist
            info!("Creating ou=people");
            let ou_people = LdapAddRequest {
                dn: format!("ou=people,{}", self.ldap.basedn),
                attributes: vec![
                    LdapAttribute {
                        atype: LDAP_ATTR_OBJECTCLASS.to_string(),
                        vals: vec![
                            "top".as_bytes().into(),
                            "organizationalUnit".as_bytes().into(),
                        ],
                    },
                    LdapAttribute {
                        atype: LDAP_ATTR_OU.to_string(),
                        vals: vec!["people".as_bytes().into()],
                    },
                ],
            };
            self.ldap.add(ou_people).await?;
        }

        let res = self
            .ldap
            .search(LdapFilter::Equality(LDAP_ATTR_OU.to_string(),LDAP_ATTR_GROUPS.to_string()))
            .await?;

        if res.is_empty() {
            // Doesn't exist
            info!("Creating ou={}", LDAP_ATTR_GROUPS);
            let ou_groups: LdapAddRequest = LdapAddRequest {
                dn: format!("ou={},{}", LDAP_ATTR_GROUPS, self.ldap.basedn),
                attributes: vec![
                    LdapAttribute {
                        atype: LDAP_ATTR_OBJECTCLASS.to_string(),
                        vals: vec![
                            "top".as_bytes().into(),
                            "organizationalUnit".as_bytes().into(),
                        ],
                    },
                    LdapAttribute {
                        atype: LDAP_ATTR_OU.to_string(),
                        vals: vec![LDAP_ATTR_GROUPS.as_bytes().into()],
                    },
                ],
            };
            self.ldap.add(ou_groups).await?;
        }

        // Now go and create the rest.
        // We stick ACI's on the rootdse, so we can clear them and reset them easier.
        for u in targets {
            // does it already exist?
            let res = self
                .ldap
                .search(LdapFilter::Equality(LDAP_ATTR_CN.to_string(), u.to_string()))
                .await?;

            if !res.is_empty() {
                continue;
            }

            let e = all_entities.get(u).unwrap();
            let dn = e.get_ds_ldap_dn(&self.ldap.basedn);
            match e {
                Entity::Account(a) => {
                    let account = LdapAddRequest {
                        dn,
                        attributes: vec![
                            LdapAttribute {
                                atype: LDAP_ATTR_OBJECTCLASS.to_string(),
                                vals: vec![
                                    "top".as_bytes().into(),
                                    "nsPerson".as_bytes().into(),
                                    "nsAccount".as_bytes().into(),
                                    "nsOrgPerson".as_bytes().into(),
                                    "posixAccount".as_bytes().into(),
                                ],
                            },
                            LdapAttribute {
                                atype: LDAP_ATTR_CN.to_string(),
                                vals: vec![a.uuid.as_bytes().to_vec()],
                            },
                            LdapAttribute {
                                atype: ATTR_UID.to_string(),
                                vals: vec![a.name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: LDAP_ATTR_DISPLAY_NAME.to_string(),
                                vals: vec![a.display_name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "userPassword".to_string(),
                                vals: vec![a.password.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "homeDirectory".to_string(),
                                vals: vec![format!("/home/{}", a.uuid).as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "uidNumber".to_string(),
                                vals: vec!["1000".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "gidNumber".to_string(),
                                vals: vec!["1000".as_bytes().into()],
                            },
                        ],
                    };
                    self.ldap.add(account).await?;
                }
                Entity::Group(g) => {
                    let group = LdapAddRequest {
                        dn,
                        attributes: vec![
                            LdapAttribute {
                                atype: LDAP_ATTR_OBJECTCLASS.to_string(),
                                vals: vec![
                                    "top".as_bytes().into(),
                                    "groupOfNames".as_bytes().into(),
                                ],
                            },
                            LdapAttribute {
                                atype: LDAP_ATTR_CN.to_string(),
                                vals: vec![g.uuid.as_bytes().to_vec(), g.name.as_bytes().into()],
                            },
                        ],
                    };
                    self.ldap.add(group).await?;
                }
            }
        }

        // Add all the members.
        for g in targets.iter().filter_map(|u| {
            let e = all_entities.get(u).unwrap();
            match e {
                Entity::Group(g) => Some(g),
                _ => None,
            }
        }) {
            // List of dns
            let vals: Vec<Vec<u8>> = g
                .members
                .iter()
                .map(|id| {
                    all_entities
                        .get(id)
                        .unwrap()
                        .get_ds_ldap_dn(&self.ldap.basedn)
                        .as_bytes()
                        .into()
                })
                .collect();

            let req = LdapModifyRequest {
                dn: g.get_ds_ldap_dn(&self.ldap.basedn),
                changes: vec![LdapModify {
                    operation: LdapModifyType::Replace,
                    modification: LdapPartialAttribute {
                        atype: "member".to_string(),
                        vals,
                    },
                }],
            };
            self.ldap.modify(req).await?;
        }
        Ok(())
    }

    pub async fn setup_access_controls(
        &self,
        access: &HashMap<Uuid, Vec<EntityType>>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        // Create top level priv groups
        let res = self
            .ldap
            .search(LdapFilter::Equality(
                LDAP_ATTR_CN.to_string(),
                "priv_account_manage".to_string(),
            ))
            .await?;

        if res.is_empty() {
            // Doesn't exist
            info!("Creating cn=priv_account_manage");
            let group = LdapAddRequest {
                dn: format!("cn=priv_account_manage,{}", self.ldap.basedn),
                attributes: vec![
                    LdapAttribute {
                        atype: LDAP_ATTR_OBJECTCLASS.to_string(),
                        vals: vec!["top".as_bytes().into(), "groupOfNames".as_bytes().into()],
                    },
                    LdapAttribute {
                        atype: LDAP_ATTR_CN.to_string(),
                        vals: vec!["priv_account_manage".as_bytes().into()],
                    },
                ],
            };
            self.ldap.add(group).await?;
        }

        let res = self
            .ldap
            .search(LdapFilter::Equality(
                LDAP_ATTR_CN.to_string(),
                "priv_group_manage".to_string(),
            ))
            .await?;

        if res.is_empty() {
            // Doesn't exist
            info!("Creating cn=priv_group_manage");
            let group = LdapAddRequest {
                dn: format!("cn=priv_group_manage,{}", self.ldap.basedn),
                attributes: vec![
                    LdapAttribute {
                        atype: LDAP_ATTR_OBJECTCLASS.to_string(),
                        vals: vec!["top".as_bytes().into(), "groupOfNames".as_bytes().into()],
                    },
                    LdapAttribute {
                        atype: LDAP_ATTR_CN.to_string(),
                        vals: vec!["priv_group_manage".as_bytes().into()],
                    },
                ],
            };
            self.ldap.add(group).await?;
        }

        // Add the acis with mod replace.
        let acimod = LdapModifyRequest {
                dn: self.ldap.basedn.clone(),
                changes: vec![
                    LdapModify {
                        operation: LdapModifyType::Replace,
                        modification: LdapPartialAttribute {
                            atype: "aci".to_string(),
                            vals: vec![
                                r#"(targetattr="dc || description || objectClass")(targetfilter="(objectClass=domain)")(version 3.0; acl "Enable anyone domain read"; allow (read, search, compare)(userdn="ldap:///anyone");)"#.as_bytes().into(),

                                r#"(targetattr="ou || objectClass")(targetfilter="(objectClass=organizationalUnit)")(version 3.0; acl "Enable anyone ou read"; allow (read, search, compare)(userdn="ldap:///anyone");)"#.as_bytes().into(),
                                r#"(targetattr="cn || member || gidNumber || nsUniqueId || description || objectClass")(targetfilter="(objectClass=groupOfNames)")(version 3.0; acl "Enable anyone group read"; allow (read, search, compare)(userdn="ldap:///anyone");)"#.as_bytes().into(),
                                format!(r#"(targetattr="cn || member || gidNumber || description || objectClass")(targetfilter="(objectClass=groupOfNames)")(version 3.0; acl "Enable group_admin to manage groups"; allow (write,add, delete)(groupdn="ldap:///cn=priv_group_manage,{}");)"#, self.ldap.basedn).as_bytes().into(),
                                r#"(targetattr="objectClass || description || nsUniqueId || uid || displayName || loginShell || uidNumber || gidNumber || gecos || homeDirectory || cn || memberOf || mail || nsSshPublicKey || nsAccountLock || userCertificate")(targetfilter="(objectClass=posixaccount)")(version 3.0; acl "Enable anyone user read"; allow (read, search, compare)(userdn="ldap:///anyone");)"#.as_bytes().into(),
                                r#"(targetattr="displayName || legalName || userPassword || nsSshPublicKey")(version 3.0; acl "Enable self partial modify"; allow (write)(userdn="ldap:///self");)"#.as_bytes().into(),
                                format!(r#"(targetattr="uid || description || displayName || loginShell || uidNumber || gidNumber || gecos || homeDirectory || cn || memberOf || mail || legalName || telephoneNumber || mobile")(targetfilter="(&(objectClass=nsPerson)(objectClass=nsAccount))")(version 3.0; acl "Enable user admin create"; allow (write, add, delete, read)(groupdn="ldap:///cn=priv_account_manage,{}");)"#, self.ldap.basedn).as_bytes().into(),
                            ]
                        }
                    }
                ]
            };
        self.ldap.modify(acimod).await?;

        // Add members as needed.
        let mut priv_account = Vec::new();
        let mut priv_group = Vec::new();

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
                priv_account.push(
                    account
                        .get_ds_ldap_dn(&self.ldap.basedn)
                        .as_bytes()
                        .to_vec(),
                )
            }
            if need_group {
                priv_group.push(
                    account
                        .get_ds_ldap_dn(&self.ldap.basedn)
                        .as_bytes()
                        .to_vec(),
                )
            }
        }

        // Sort and dedup
        priv_account.sort_unstable();
        priv_group.sort_unstable();
        priv_account.dedup();
        priv_group.dedup();
        // Do the mod in one pass.
        info!("Setting up cn=priv_group_manage");
        let req = LdapModifyRequest {
            dn: format!("cn=priv_group_manage,{}", self.ldap.basedn),
            changes: vec![LdapModify {
                operation: LdapModifyType::Delete,
                modification: LdapPartialAttribute {
                    atype: "member".to_string(),
                    vals: priv_group,
                },
            }],
        };
        let _ = self.ldap.modify(req).await;

        info!("Setting up cn=priv_account_manage");
        let req = LdapModifyRequest {
            dn: format!("cn=priv_account_manage,{}", self.ldap.basedn),
            changes: vec![LdapModify {
                operation: LdapModifyType::Delete,
                modification: LdapPartialAttribute {
                    atype: "member".to_string(),
                    vals: priv_account,
                },
            }],
        };
        let _ = self.ldap.modify(req).await;
        Ok(())
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
