//! LDAP specific operations handling components. This is where LDAP operations
//! are sent to for processing.

use crate::event::SearchEvent;
use crate::idm::event::LdapAuthEvent;
use crate::idm::server::{IdmServer, IdmServerTransaction};
use crate::prelude::*;
use async_std::task;
use kanidm_proto::v1::{OperationError, UserAuthToken};
use ldap3_server::simple::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::iter;
use uuid::Uuid;

// Clippy doesn't like Bind here. But proto needs unboxed ldapmsg,
// and ldapboundtoken is moved. Really, it's not too bad, every message here is pretty sucky.
#[allow(clippy::large_enum_variant)]
pub enum LdapResponseState {
    Unbind,
    Disconnect(LdapMsg),
    Bind(LdapBoundToken, LdapMsg),
    Respond(LdapMsg),
    MultiPartResponse(Vec<LdapMsg>),
    BindMultiPartResponse(LdapBoundToken, Vec<LdapMsg>),
}

#[derive(Debug, Clone)]
pub struct LdapBoundToken {
    pub spn: String,
    pub uuid: Uuid,
    // For now, always anonymous
    pub effective_uat: UserAuthToken,
}

pub struct LdapServer {
    rootdse: LdapSearchResultEntry,
    basedn: String,
    dnre: Regex,
    binddnre: Regex,
}

impl LdapServer {
    pub fn new(audit: &mut AuditScope, idms: &IdmServer) -> Result<Self, OperationError> {
        // let ct = duration_from_epoch_now();
        let idms_prox_read = task::block_on(idms.proxy_read_async());
        // This is the rootdse path.
        // get the domain_info item
        let domain_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(audit, &UUID_DOMAIN_INFO)?;

        let domain_name = domain_entry
            .get_ava_single_str("domain_name")
            .map(|s| s.to_string())
            .ok_or(OperationError::InvalidEntryState)?;

        let basedn = ldap_domain_to_dc(domain_name.as_str());

        let dnre = Regex::new(format!("^((?P<attr>[^=]+)=(?P<val>[^=]+),)?{}$", basedn).as_str())
            .map_err(|_| OperationError::InvalidEntryState)?;

        let binddnre = Regex::new(format!("^(([^=,]+)=)?(?P<val>[^=,]+)(,{})?$", basedn).as_str())
            .map_err(|_| OperationError::InvalidEntryState)?;

        let rootdse = LdapSearchResultEntry {
            dn: "".to_string(),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "objectClass".to_string(),
                    vals: vec!["top".to_string()],
                },
                LdapPartialAttribute {
                    atype: "vendorName".to_string(),
                    vals: vec!["Kanidm Project".to_string()],
                },
                LdapPartialAttribute {
                    atype: "vendorVersion".to_string(),
                    vals: vec!["kanidm_ldap_1.0.0".to_string()],
                },
                LdapPartialAttribute {
                    atype: "supportedLDAPVersion".to_string(),
                    vals: vec!["3".to_string()],
                },
                LdapPartialAttribute {
                    atype: "supportedExtension".to_string(),
                    vals: vec!["1.3.6.1.4.1.4203.1.11.3".to_string()],
                },
                LdapPartialAttribute {
                    atype: "supportedFeatures".to_string(),
                    vals: vec!["1.3.6.1.4.1.4203.1.5.1".to_string()],
                },
                LdapPartialAttribute {
                    atype: "defaultnamingcontext".to_string(),
                    vals: vec![basedn.clone()],
                },
            ],
        };

        Ok(LdapServer {
            rootdse,
            basedn,
            dnre,
            binddnre,
        })
    }

    async fn do_search(
        &self,
        audit: &mut AuditScope,
        idms: &IdmServer,
        sr: &SearchRequest,
        uat: &LdapBoundToken,
        // eventid: &Uuid,
    ) -> Result<Vec<LdapMsg>, OperationError> {
        ladmin_info!(audit, "Attempt LDAP Search for {}", uat.spn);
        // If the request is "", Base, Present("objectclass"), [], then we want the rootdse.
        if sr.base.is_empty() && sr.scope == LdapSearchScope::Base {
            ladmin_info!(audit, "LDAP Search success - RootDSE");
            Ok(vec![
                sr.gen_result_entry(self.rootdse.clone()),
                sr.gen_success(),
            ])
        } else {
            // We want something else apparently. Need to do some more work ...
            // Parse the operation and make sure it's sane before we start the txn.

            // This scoping returns an extra filter component.

            let (opt_attr, opt_value) = match self.dnre.captures(sr.base.as_str()) {
                Some(caps) => (
                    caps.name("attr").map(|v| v.as_str().to_string()),
                    caps.name("val").map(|v| v.as_str().to_string()),
                ),
                None => {
                    lrequest_error!(audit, "LDAP Search failure - invalid basedn");
                    return Err(OperationError::InvalidRequestState);
                }
            };

            let req_dn = match (opt_attr, opt_value) {
                (Some(a), Some(v)) => Some((a, v)),
                (None, None) => None,
                _ => {
                    lrequest_error!(audit, "LDAP Search failure - invalid rdn");
                    return Err(OperationError::InvalidRequestState);
                }
            };

            ltrace!(audit, "RDN -> {:?}", req_dn);

            // Map the Some(a,v) to ...?

            let ext_filter = match (&sr.scope, req_dn) {
                (LdapSearchScope::OneLevel, Some(_r)) => return Ok(vec![sr.gen_success()]),
                (LdapSearchScope::OneLevel, None) => {
                    // exclude domain_info
                    Some(LdapFilter::Not(Box::new(LdapFilter::Equality(
                        "uuid".to_string(),
                        STR_UUID_DOMAIN_INFO.to_string(),
                    ))))
                }
                (LdapSearchScope::Base, Some((a, v))) => Some(LdapFilter::Equality(a, v)),
                (LdapSearchScope::Base, None) => {
                    // domain_info
                    Some(LdapFilter::Equality(
                        "uuid".to_string(),
                        STR_UUID_DOMAIN_INFO.to_string(),
                    ))
                }
                (LdapSearchScope::Subtree, Some((a, v))) => Some(LdapFilter::Equality(a, v)),
                (LdapSearchScope::Subtree, None) => {
                    // No filter changes needed.
                    None
                }
            };

            let mut all_attrs = false;
            let mut all_op_attrs = false;

            // TODO #67: limit the number of attributes here!
            if sr.attrs.is_empty() {
                // If [], then "all" attrs
                all_attrs = true;
            } else {
                sr.attrs.iter().for_each(|a| {
                    if a == "*" {
                        all_attrs = true;
                    } else if a == "+" {
                        // This forces the BE to get all the attrs so we can
                        // map all vattrs.
                        all_attrs = true;
                        all_op_attrs = true;
                    }
                })
            }

            // We need to retain this to know what the client requested.
            let (k_attrs, l_attrs) = if all_op_attrs {
                // We need all attrs, and we do a full v_attr map.
                (None, ldap_all_vattrs())
            } else if all_attrs {
                (None, Vec::new())
            } else {
                // What the client requested, in LDAP forms.
                let req_attrs: Vec<String> = sr
                    .attrs
                    .iter()
                    .filter_map(|a| {
                        if a == "*" || a == "+" {
                            None
                        } else {
                            Some(a.to_lowercase())
                        }
                    })
                    .collect();
                // This is what the client requested, but mapped to kanidm forms.
                // NOTE: All req_attrs are lowercase at this point.
                let mapped_attrs: BTreeSet<_> = req_attrs
                    .iter()
                    .filter_map(|a| {
                        // EntryDN and DN have special handling in to_ldap in Entry. We don't
                        // need these here, we know they will be returned as part of the transform.
                        if a == "entrydn" || a == "dn" {
                            None
                        } else {
                            Some(AttrString::from(ldap_vattr_map(a)))
                        }
                    })
                    .collect();

                (Some(mapped_attrs), req_attrs)
            };

            ladmin_info!(audit, "LDAP Search Request LDAP Attrs -> {:?}", l_attrs);
            ladmin_info!(audit, "LDAP Search Request Mapped Attrs -> {:?}", k_attrs);

            let ct = duration_from_epoch_now();
            let idm_read = idms.proxy_read_async().await;
            lperf_segment!(audit, "ldap::do_search<core>", || {
                // Now start the txn - we need it for resolving filter components.

                // join the filter, with ext_filter
                let lfilter = match ext_filter {
                    Some(ext) => LdapFilter::And(vec![
                        sr.filter.clone(),
                        ext,
                        LdapFilter::Not(Box::new(LdapFilter::Or(vec![
                            LdapFilter::Equality("class".to_string(), "classtype".to_string()),
                            LdapFilter::Equality("class".to_string(), "attributetype".to_string()),
                            LdapFilter::Equality(
                                "class".to_string(),
                                "access_control_profile".to_string(),
                            ),
                        ]))),
                    ]),
                    None => LdapFilter::And(vec![
                        sr.filter.clone(),
                        LdapFilter::Not(Box::new(LdapFilter::Or(vec![
                            LdapFilter::Equality("class".to_string(), "classtype".to_string()),
                            LdapFilter::Equality("class".to_string(), "attributetype".to_string()),
                            LdapFilter::Equality(
                                "class".to_string(),
                                "access_control_profile".to_string(),
                            ),
                        ]))),
                    ]),
                };

                ladmin_info!(audit, "LDAP Search Filter -> {:?}", lfilter);

                // Build the event, with the permissions from effective_uuid
                // (should always be anonymous at the moment)
                // ! Remember, searchEvent wraps to ignore hidden for us.
                let se = lperf_trace_segment!(audit, "ldap::do_search<core><prepare_se>", || {
                    let ident = idm_read
                        .process_uat_to_identity(audit, &uat.effective_uat, ct)
                        .map_err(|e| {
                            ladmin_error!(audit, "Invalid identity: {:?}", e);
                            e
                        })?;
                    SearchEvent::new_ext_impersonate_uuid(
                        audit,
                        &idm_read.qs_read,
                        ident,
                        &lfilter,
                        k_attrs,
                    )
                })
                .map_err(|e| {
                    ladmin_error!(audit, "failed to create search event -> {:?}", e);
                    e
                })?;

                let res = idm_read.qs_read.search_ext(audit, &se).map_err(|e| {
                    ladmin_error!(audit, "search failure {:?}", e);
                    e
                })?;

                // These have already been fully reduced (access controls applied),
                // so we can just transform the values and open palm slam them into
                // the result structure.
                let lres =
                    lperf_trace_segment!(audit, "ldap::do_search<core><prepare results>", || {
                        let lres: Result<Vec<_>, _> = res
                            .into_iter()
                            .map(|e| {
                                e.to_ldap(
                                    audit,
                                    &idm_read.qs_read,
                                    self.basedn.as_str(),
                                    all_attrs,
                                    &l_attrs,
                                )
                                // if okay, wrap in a ldap msg.
                                .map(|r| sr.gen_result_entry(r))
                            })
                            .chain(iter::once(Ok(sr.gen_success())))
                            .collect();
                        lres
                    });

                let lres = lres.map_err(|e| {
                    ladmin_error!(audit, "entry resolve failure {:?}", e);
                    e
                })?;

                ladmin_info!(
                    audit,
                    "LDAP Search Success -> number of entries {}",
                    lres.len()
                );

                Ok(lres)
            })
        }
    }

    async fn do_bind(
        &self,
        audit: &mut AuditScope,
        idms: &IdmServer,
        dn: &str,
        pw: &str,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        lsecurity!(
            audit,
            "Attempt LDAP Bind for {}",
            if dn.is_empty() { "anonymous" } else { dn }
        );
        let ct = duration_from_epoch_now();

        let mut idm_auth = idms.auth_async().await;

        let target_uuid: Uuid = if dn.is_empty() {
            if pw.is_empty() {
                lsecurity!(audit, "✅ LDAP Bind success anonymous");
                *UUID_ANONYMOUS
            } else {
                lsecurity!(audit, "❌ LDAP Bind failure anonymous");
                // Yeah-nahhhhh
                return Ok(None);
            }
        } else {
            let rdn = match self
                .binddnre
                .captures(dn)
                .and_then(|caps| caps.name("val").map(|v| v.as_str().to_string()))
            {
                Some(r) => r,
                None => return Err(OperationError::NoMatchingEntries),
            };

            ltrace!(audit, "rdn val is -> {:?}", rdn);

            if rdn.is_empty() {
                // That's weird ...
                return Err(OperationError::NoMatchingEntries);
            }

            idm_auth
                .qs_read
                .name_to_uuid(audit, rdn.as_str())
                .map_err(|e| {
                    lrequest_error!(audit, "Error resolving rdn to target {:?} {:?}", rdn, e);
                    e
                })?
        };

        let lae = LdapAuthEvent::from_parts(audit, target_uuid, pw.to_string())?;
        idm_auth.auth_ldap(audit, &lae, ct).await.and_then(|r| {
            idm_auth.commit(audit).map(|_| {
                if r.is_some() {
                    lsecurity!(audit, "✅ LDAP Bind success {}", dn);
                } else {
                    lsecurity!(audit, "❌ LDAP Bind failure {}", dn);
                };
                r
            })
        })
    }

    pub async fn do_op(
        &self,
        audit: &mut AuditScope,
        idms: &IdmServer,
        server_op: ServerOps,
        uat: Option<LdapBoundToken>,
        eventid: &Uuid,
    ) -> Result<LdapResponseState, OperationError> {
        match server_op {
            ServerOps::SimpleBind(sbr) => self
                .do_bind(audit, idms, sbr.dn.as_str(), sbr.pw.as_str())
                .await
                .map(|r| match r {
                    Some(lbt) => LdapResponseState::Bind(lbt, sbr.gen_success()),
                    None => LdapResponseState::Respond(sbr.gen_invalid_cred()),
                })
                .or_else(|e| {
                    let (rc, msg) = operationerr_to_ldapresultcode(e);
                    Ok(LdapResponseState::Respond(sbr.gen_error(rc, msg)))
                }),
            ServerOps::Search(sr) => match uat {
                Some(u) => self
                    .do_search(audit, idms, &sr, &u)
                    .await
                    .map(LdapResponseState::MultiPartResponse)
                    .or_else(|e| {
                        let (rc, msg) = operationerr_to_ldapresultcode(e);
                        Ok(LdapResponseState::Respond(sr.gen_error(rc, msg)))
                    }),
                None => {
                    // Search can occur without a bind, so bind first.
                    let lbt = match self.do_bind(audit, idms, "", "").await {
                        Ok(Some(lbt)) => lbt,
                        Ok(None) => {
                            return Ok(LdapResponseState::Respond(
                                sr.gen_error(LdapResultCode::InvalidCredentials, "".to_string()),
                            ))
                        }
                        Err(e) => {
                            let (rc, msg) = operationerr_to_ldapresultcode(e);
                            return Ok(LdapResponseState::Respond(sr.gen_error(rc, msg)));
                        }
                    };
                    // If okay, do the search.
                    self.do_search(audit, idms, &sr, &lbt)
                        .await
                        .map(|r| LdapResponseState::BindMultiPartResponse(lbt, r))
                        .or_else(|e| {
                            let (rc, msg) = operationerr_to_ldapresultcode(e);
                            Ok(LdapResponseState::Respond(sr.gen_error(rc, msg)))
                        })
                }
            },
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                Ok(LdapResponseState::Unbind)
            }
            ServerOps::Whoami(wr) => match uat {
                Some(u) => Ok(LdapResponseState::Respond(
                    wr.gen_success(format!("u: {}", u.spn).as_str()),
                )),
                None => Ok(LdapResponseState::Respond(wr.gen_operror(
                    format!("Unbound Connection {:?}", &eventid).as_str(),
                ))),
            },
        } // end match server op
    }
}

fn ldap_domain_to_dc(input: &str) -> String {
    let mut output: String = String::new();
    input.split('.').for_each(|dc| {
        output.push_str("dc=");
        output.push_str(dc);
        #[allow(clippy::single_char_pattern, clippy::single_char_add_str)]
        output.push_str(",");
    });
    // Remove the last ','
    output.pop();
    output
}

fn operationerr_to_ldapresultcode(e: OperationError) -> (LdapResultCode, String) {
    match e {
        OperationError::InvalidRequestState => {
            (LdapResultCode::ConstraintViolation, "".to_string())
        }
        OperationError::InvalidAttributeName(s) | OperationError::InvalidAttribute(s) => {
            (LdapResultCode::InvalidAttributeSyntax, s)
        }
        OperationError::SchemaViolation(se) => {
            (LdapResultCode::UnwillingToPerform, format!("{:?}", se))
        }
        e => (LdapResultCode::Other, format!("{:?}", e)),
    }
}

#[inline]
pub(crate) fn ldap_all_vattrs() -> Vec<String> {
    vec![
        "entryuuid".to_string(),
        "objectclass".to_string(),
        "entrydn".to_string(),
        "email".to_string(),
        "emailaddress".to_string(),
        "keys".to_string(),
        "sshpublickey".to_string(),
        "cn".to_string(),
        "uidnumber".to_string(),
    ]
}

#[inline]
pub(crate) fn ldap_vattr_map(input: &str) -> &str {
    // ⚠️  WARNING ⚠️
    // If you modify this list you MUST add these values to
    // corresponding phantom attributes in the schema to prevent
    // incorrect future or duplicate usage.
    //
    //   LDAP NAME     KANI ATTR SOURCE NAME
    match input {
        "entryuuid" => "uuid",
        "objectclass" => "class",
        "email" => "mail",
        "emailaddress" => "mail",
        "keys" => "ssh_publickey",
        "sshpublickey" => "ssh_publickey",
        "cn" => "name",
        "uidnumber" => "gidnumber",
        a => a,
    }
}

#[inline]
pub(crate) fn ldap_attr_filter_map(input: &str) -> AttrString {
    AttrString::from(ldap_vattr_map(&input.to_lowercase()))
}

#[cfg(test)]
mod tests {
    // use crate::prelude::*;
    use crate::event::{CreateEvent, ModifyEvent};
    use crate::idm::event::UnixPasswordChangeEvent;
    use crate::ldap::LdapServer;
    use crate::modify::{Modify, ModifyList};
    use async_std::task;
    use ldap3_server::proto::{LdapFilter, LdapOp, LdapSearchScope};
    use ldap3_server::simple::*;
    use std::collections::HashSet;

    const TEST_PASSWORD: &'static str = "ntaoeuntnaoeuhraohuercahu😍";

    #[test]
    fn test_ldap_simple_bind() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       au: &mut AuditScope| {
            let ldaps = LdapServer::new(au, idms).expect("failed to start ldap");

            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            // make the admin a valid posix account
            let me_posix = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("admin"))),
                    ModifyList::new_list(vec![
                        Modify::Present(
                            AttrString::from("class"),
                            Value::new_class("posixaccount"),
                        ),
                        Modify::Present(AttrString::from("gidnumber"), Value::new_uint32(2001)),
                    ]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(au, &me_posix).is_ok());

            let pce = UnixPasswordChangeEvent::new_internal(&UUID_ADMIN, TEST_PASSWORD);

            assert!(idms_prox_write.set_unix_account_password(au, &pce).is_ok());
            assert!(idms_prox_write.commit(au).is_ok());

            let anon_t = task::block_on(ldaps.do_bind(au, idms, "", ""))
                .unwrap()
                .unwrap();
            assert!(anon_t.uuid == *UUID_ANONYMOUS);
            assert!(task::block_on(ldaps.do_bind(au, idms, "", "test"))
                .unwrap()
                .is_none());

            // Now test the admin and various DN's
            let admin_t = task::block_on(ldaps.do_bind(au, idms, "admin", TEST_PASSWORD))
                .unwrap()
                .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t =
                task::block_on(ldaps.do_bind(au, idms, "admin@example.com", TEST_PASSWORD))
                    .unwrap()
                    .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t = task::block_on(ldaps.do_bind(au, idms, STR_UUID_ADMIN, TEST_PASSWORD))
                .unwrap()
                .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t = task::block_on(ldaps.do_bind(
                au,
                idms,
                "name=admin,dc=example,dc=com",
                TEST_PASSWORD,
            ))
            .unwrap()
            .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t = task::block_on(ldaps.do_bind(
                au,
                idms,
                "spn=admin@example.com,dc=example,dc=com",
                TEST_PASSWORD,
            ))
            .unwrap()
            .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t = task::block_on(ldaps.do_bind(
                au,
                idms,
                format!("uuid={},dc=example,dc=com", STR_UUID_ADMIN).as_str(),
                TEST_PASSWORD,
            ))
            .unwrap()
            .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);

            let admin_t = task::block_on(ldaps.do_bind(au, idms, "name=admin", TEST_PASSWORD))
                .unwrap()
                .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t =
                task::block_on(ldaps.do_bind(au, idms, "spn=admin@example.com", TEST_PASSWORD))
                    .unwrap()
                    .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t = task::block_on(ldaps.do_bind(
                au,
                idms,
                format!("uuid={}", STR_UUID_ADMIN).as_str(),
                TEST_PASSWORD,
            ))
            .unwrap()
            .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);

            let admin_t =
                task::block_on(ldaps.do_bind(au, idms, "admin,dc=example,dc=com", TEST_PASSWORD))
                    .unwrap()
                    .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t = task::block_on(ldaps.do_bind(
                au,
                idms,
                "admin@example.com,dc=example,dc=com",
                TEST_PASSWORD,
            ))
            .unwrap()
            .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);
            let admin_t = task::block_on(ldaps.do_bind(
                au,
                idms,
                format!("{},dc=example,dc=com", STR_UUID_ADMIN).as_str(),
                TEST_PASSWORD,
            ))
            .unwrap()
            .unwrap();
            assert!(admin_t.uuid == *UUID_ADMIN);

            // Bad password, check last to prevent softlocking of the admin account.
            assert!(task::block_on(ldaps.do_bind(au, idms, "admin", "test"))
                .unwrap()
                .is_none());

            // Non-existant and invalid DNs
            assert!(task::block_on(ldaps.do_bind(
                au,
                idms,
                "spn=admin@example.com,dc=clownshoes,dc=example,dc=com",
                TEST_PASSWORD
            ))
            .is_err());
            assert!(task::block_on(ldaps.do_bind(
                au,
                idms,
                "spn=claire@example.com,dc=example,dc=com",
                TEST_PASSWORD
            ))
            .is_err());
            assert!(
                task::block_on(ldaps.do_bind(au, idms, ",dc=example,dc=com", TEST_PASSWORD))
                    .is_err()
            );
            assert!(
                task::block_on(ldaps.do_bind(au, idms, "dc=example,dc=com", TEST_PASSWORD))
                    .is_err()
            );

            assert!(task::block_on(ldaps.do_bind(au, idms, "claire", "test")).is_err());
        })
    }

    macro_rules! assert_entry_contains {
        (
            $e:expr,
            $dn:expr,
            $($item:expr),*
        ) => {{
            assert!($e.dn == $dn);
            // Build a set from the attrs.
            let mut attrs = HashSet::new();
            for a in $e.attributes.iter() {
                for v in a.vals.iter() {
                    attrs.insert((a.atype.as_str(), v.as_str()));
                }
            };
            $(
                assert!(attrs.contains(&(
                    $item.0, $item.1
                )));
            )*

        }};
    }

    #[test]
    fn test_ldap_virtual_attribute_generation() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &IdmServerDelayed,
                       audit: &mut AuditScope| {
            let ldaps = LdapServer::new(audit, idms).expect("failed to start ldap");

            let ssh_ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst";

            // Setup a user we want to check.
            {
                let e1 = entry_init!(
                    ("class", Value::new_class("object")),
                    ("class", Value::new_class("person")),
                    ("class", Value::new_class("account")),
                    ("class", Value::new_class("posixaccount")),
                    ("name", Value::new_iname("testperson1")),
                    (
                        "uuid",
                        Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                    ),
                    ("description", Value::new_utf8s("testperson1")),
                    ("displayname", Value::new_utf8s("testperson1")),
                    ("gidnumber", Value::new_uint32(12345678)),
                    ("loginshell", Value::new_iutf8("/bin/zsh")),
                    ("ssh_publickey", Value::new_sshkey_str("test", ssh_ed25519))
                );

                let server_txn = idms.proxy_write(duration_from_epoch_now());
                let ce = CreateEvent::new_internal(vec![e1]);
                assert!(server_txn
                    .qs_write
                    .create(audit, &ce)
                    .and_then(|_| server_txn.commit(audit))
                    .is_ok());
            }

            // Setup the anonymous login.
            let anon_t = task::block_on(ldaps.do_bind(audit, idms, "", ""))
                .unwrap()
                .unwrap();
            assert!(anon_t.uuid == *UUID_ANONYMOUS);

            // Check that when we request *, we get default list.
            let sr = SearchRequest {
                msgid: 1,
                base: "dc=example,dc=com".to_string(),
                scope: LdapSearchScope::Subtree,
                filter: LdapFilter::Equality("name".to_string(), "testperson1".to_string()),
                attrs: vec!["*".to_string()],
            };
            let r1 = task::block_on(ldaps.do_search(audit, idms, &sr, &anon_t)).unwrap();

            // The result, and the ldap proto success msg.
            assert!(r1.len() == 2);
            match &r1[0].op {
                LdapOp::SearchResultEntry(lsre) => {
                    assert_entry_contains!(
                        lsre,
                        "spn=testperson1@example.com,dc=example,dc=com",
                        ("class", "object"),
                        ("class", "person"),
                        ("class", "account"),
                        ("class", "posixaccount"),
                        ("displayname", "testperson1"),
                        ("name", "testperson1"),
                        ("gidnumber", "12345678"),
                        ("loginshell", "/bin/zsh"),
                        ("ssh_publickey", ssh_ed25519),
                        ("uuid", "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                    );
                }
                _ => assert!(false),
            };

            // Check that when we request +, we get all attrs and the vattrs
            let sr = SearchRequest {
                msgid: 1,
                base: "dc=example,dc=com".to_string(),
                scope: LdapSearchScope::Subtree,
                filter: LdapFilter::Equality("name".to_string(), "testperson1".to_string()),
                attrs: vec!["+".to_string()],
            };
            let r1 = task::block_on(ldaps.do_search(audit, idms, &sr, &anon_t)).unwrap();

            // The result, and the ldap proto success msg.
            assert!(r1.len() == 2);
            match &r1[0].op {
                LdapOp::SearchResultEntry(lsre) => {
                    assert_entry_contains!(
                        lsre,
                        "spn=testperson1@example.com,dc=example,dc=com",
                        ("objectclass", "object"),
                        ("objectclass", "person"),
                        ("objectclass", "account"),
                        ("objectclass", "posixaccount"),
                        ("displayname", "testperson1"),
                        ("name", "testperson1"),
                        ("gidnumber", "12345678"),
                        ("loginshell", "/bin/zsh"),
                        ("ssh_publickey", ssh_ed25519),
                        ("entryuuid", "cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                        ("entrydn", "spn=testperson1@example.com,dc=example,dc=com"),
                        ("uidnumber", "12345678"),
                        ("cn", "testperson1"),
                        ("keys", ssh_ed25519)
                    );
                }
                _ => assert!(false),
            };

            // Check that when we request an attr by name, we get all of them correctly.
            let sr = SearchRequest {
                msgid: 1,
                base: "dc=example,dc=com".to_string(),
                scope: LdapSearchScope::Subtree,
                filter: LdapFilter::Equality("name".to_string(), "testperson1".to_string()),
                attrs: vec![
                    "name".to_string(),
                    "entrydn".to_string(),
                    "keys".to_string(),
                    "uidnumber".to_string(),
                ],
            };
            let r1 = task::block_on(ldaps.do_search(audit, idms, &sr, &anon_t)).unwrap();

            // The result, and the ldap proto success msg.
            assert!(r1.len() == 2);
            match &r1[0].op {
                LdapOp::SearchResultEntry(lsre) => {
                    assert_entry_contains!(
                        lsre,
                        "spn=testperson1@example.com,dc=example,dc=com",
                        ("name", "testperson1"),
                        ("entrydn", "spn=testperson1@example.com,dc=example,dc=com"),
                        ("uidnumber", "12345678"),
                        ("keys", ssh_ed25519)
                    );
                }
                _ => assert!(false),
            };
        })
    }
}
