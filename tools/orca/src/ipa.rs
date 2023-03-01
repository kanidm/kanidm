use ldap3_proto::proto::*;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
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

        Ok(IpaServer {
            ldap,
            realm,
            admin_pw,
        })
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
        // todo!();
        Ok(())
    }

    pub async fn setup_admin_precreate_entities(
        &self,
        targets: &HashSet<Uuid>,
        all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        for u in targets {
            let e = all_entities.get(u).unwrap();
            // does it already exist?
            let res = self
                .ldap
                .search(LdapFilter::Equality(
                    "cn".to_string(),
                    e.get_name().to_string(),
                ))
                .await?;

            if !res.is_empty() {
                continue;
            }

            let dn = e.get_ipa_ldap_dn(&self.ldap.basedn);
            match e {
                Entity::Account(a) => {
                    let account = LdapAddRequest {
                        dn,
                        attributes: vec![
                            LdapAttribute {
                                atype: "objectClass".to_string(),
                                vals: vec![
                                    "ipaobject".as_bytes().into(),
                                    "person".as_bytes().into(),
                                    "top".as_bytes().into(),
                                    "ipasshuser".as_bytes().into(),
                                    "inetorgperson".as_bytes().into(),
                                    "organizationalperson".as_bytes().into(),
                                    "krbticketpolicyaux".as_bytes().into(),
                                    "krbprincipalaux".as_bytes().into(),
                                    "inetuser".as_bytes().into(),
                                    "posixaccount".as_bytes().into(),
                                    "meporiginentry".as_bytes().into(),
                                ],
                            },
                            LdapAttribute {
                                atype: "ipauniqueid".to_string(),
                                vals: vec!["autogenerate".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "uid".to_string(),
                                vals: vec![a.name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "cn".to_string(),
                                vals: vec![a.name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "givenName".to_string(),
                                vals: vec![a.name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "sn".to_string(),
                                vals: vec![a.name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "displayName".to_string(),
                                vals: vec![a.display_name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "gecos".to_string(),
                                vals: vec![a.display_name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "userPassword".to_string(),
                                vals: vec![a.password.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "initials".to_string(),
                                vals: vec!["tu".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "homeDirectory".to_string(),
                                vals: vec![format!("/home/{}", a.name).as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "mail".to_string(),
                                vals: vec![format!("{}@{}", a.name, self.realm).as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "loginshell".to_string(),
                                vals: vec!["/bin/zsh".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "uidNumber".to_string(),
                                vals: vec!["-1".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "gidNumber".to_string(),
                                vals: vec!["-1".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "krbextradata".to_string(),
                                vals: vec!["placeholder".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "krblastpwdchange".to_string(),
                                vals: vec!["20230119053224Z".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "krbPasswordExpiration".to_string(),
                                vals: vec!["20380119053224Z".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "krbPrincipalName".to_string(),
                                vals: vec![format!("{}@{}", a.name, self.realm.to_uppercase())
                                    .as_bytes()
                                    .into()],
                            },
                            LdapAttribute {
                                atype: "krbCanonicalName".to_string(),
                                vals: vec![format!("{}@{}", a.name, self.realm.to_uppercase())
                                    .as_bytes()
                                    .into()],
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
                                atype: "objectClass".to_string(),
                                vals: vec![
                                    "top".as_bytes().into(),
                                    "groupofnames".as_bytes().into(),
                                    "nestedgroup".as_bytes().into(),
                                    "ipausergroup".as_bytes().into(),
                                    "ipaobject".as_bytes().into(),
                                    "posixgroup".as_bytes().into(),
                                ],
                            },
                            LdapAttribute {
                                atype: "cn".to_string(),
                                vals: vec![g.name.as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "ipauniqueid".to_string(),
                                vals: vec!["autogenerate".as_bytes().into()],
                            },
                            LdapAttribute {
                                atype: "gidNumber".to_string(),
                                vals: vec!["-1".as_bytes().into()],
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
                        .get_ipa_ldap_dn(&self.ldap.basedn)
                        .as_bytes()
                        .into()
                })
                .collect();

            let req = LdapModifyRequest {
                dn: g.get_ipa_ldap_dn(&self.ldap.basedn),
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
        _access: &HashMap<Uuid, Vec<EntityType>>,
        _all_entities: &HashMap<Uuid, Entity>,
    ) -> Result<(), ()> {
        // todo!();
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
