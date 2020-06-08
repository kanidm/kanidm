use crate::audit::AuditScope;
use crate::constants::{STR_UUID_DOMAIN_INFO, UUID_ANONYMOUS, UUID_DOMAIN_INFO};
use crate::event::SearchEvent;
use crate::filter::Filter;
use crate::idm::event::LdapAuthEvent;
use crate::idm::server::IdmServer;
use crate::server::QueryServerTransaction;
use kanidm_proto::v1::OperationError;
use ldap3_server::simple::*;
use std::collections::BTreeSet;
use std::iter;
use std::time::SystemTime;
use uuid::Uuid;

use regex::Regex;

pub enum LdapResponseState {
    Unbind,
    Disconnect(LdapMsg),
    Bind(LdapBoundToken, LdapMsg),
    Respond(LdapMsg),
    MultiPartResponse(Vec<LdapMsg>),
}

#[derive(Debug, Clone)]
pub struct LdapBoundToken {
    pub spn: String,
    pub uuid: Uuid,
    // For now, always anonymous
    pub effective_uuid: Uuid,
}

pub struct LdapServer {
    rootdse: LdapSearchResultEntry,
    basedn: String,
    dnre: Regex,
}

impl LdapServer {
    pub fn new(au: &mut AuditScope, idms: &IdmServer) -> Result<Self, OperationError> {
        let mut idms_prox_read = idms.proxy_read();
        // This is the rootdse path.
        // get the domain_info item
        let domain_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(au, &UUID_DOMAIN_INFO)?;

        let domain_name = domain_entry
            .get_ava_single_string("domain_name")
            .ok_or(OperationError::InvalidEntryState)?;

        let basedn = ldap_domain_to_dc(domain_name.as_str());

        let dnre = Regex::new(format!("^((?P<attr>[^=]+)=(?P<val>[^=]+),)?{}$", basedn).as_str())
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
                    atype: "defaultnamingcontext".to_string(),
                    vals: vec![basedn.clone()],
                },
            ],
        };

        Ok(LdapServer {
            basedn,
            rootdse,
            dnre,
        })
    }

    fn do_search(
        &self,
        au: &mut AuditScope,
        idms: &IdmServer,
        sr: SearchRequest,
        uat: LdapBoundToken,
        // eventid: &Uuid,
    ) -> Result<LdapResponseState, OperationError> {
        // If the request is "", Base, Present("objectclass"), [], then we want the rootdse.
        if sr.base == "" && sr.scope == LdapSearchScope::Base {
            Ok(LdapResponseState::MultiPartResponse(vec![
                sr.gen_result_entry(self.rootdse.clone()),
                sr.gen_success(),
            ]))
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
                    ladmin_info!(au, "This request seems fishy ... 🐟");
                    return Err(OperationError::InvalidRequestState);
                }
            };

            let req_dn = match (opt_attr, opt_value) {
                (Some(a), Some(v)) => Some((a, v)),
                (None, None) => None,
                _ => {
                    ladmin_info!(au, "This rdn seems fishy ... 🐟");
                    return Err(OperationError::InvalidRequestState);
                }
            };

            ltrace!(au, "RDN -> {:?}", req_dn);

            // Map the Some(a,v) to ...?

            let ext_filter = match (&sr.scope, req_dn) {
                (LdapSearchScope::OneLevel, Some(r)) => {
                    return Ok(LdapResponseState::Respond(sr.gen_success()))
                }
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

            // TODO #67: limit the number of attributes here!
            let attrs = if sr.attrs.len() == 0 {
                // If [], then "all" attrs
                None
            } else {
                let mut all_attrs = false;
                let attrs: BTreeSet<_> = sr
                    .attrs
                    .iter()
                    .filter_map(|a| {
                        if a == "*" {
                            // if *, then all
                            all_attrs = true;
                            None
                        } else if a == "+" {
                            // if +, then ignore (kanidm doesn't have operational) this part.
                            None
                        } else {
                            // if list, add to the search
                            Some(a.clone())
                        }
                    })
                    .collect();
                if all_attrs {
                    None
                } else {
                    Some(attrs)
                }
            };

            ltrace!(au, "Attrs -> {:?}", attrs);

            lperf_segment!(au, "ldap::do_search<core>", || {
                // Now start the txn - we need it for resolving filter components.
                let mut idm_read = idms.proxy_read();

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

                ltrace!(au, "ldapfilter -> {:?}", lfilter);

                // Kanidm Filter from LdapFilter
                let filter =
                    Filter::from_ldap_ro(au, &lfilter, &mut idm_read.qs_read).map_err(|e| {
                        lrequest_error!(au, "invalid ldap filter {:?}", e);
                        e
                    })?;

                // Build the event, with the permissions from effective_uuid
                // (should always be anonymous at the moment)
                // ! Remember, searchEvent wraps to ignore hidden for us.
                let se = lperf_segment!(au, "ldap::do_search<core><prepare_se>", || {
                    SearchEvent::new_ext_impersonate_uuid(
                        au,
                        &mut idm_read.qs_read,
                        &uat.effective_uuid,
                        filter,
                        attrs,
                    )
                })?;

                let res = idm_read.qs_read.search_ext(au, &se).map_err(|e| {
                    ladmin_error!(au, "search failure {:?}", e);
                    e
                })?;

                // These have already been fully reduced, so we can just slap it into the result.
                let lres = lperf_segment!(au, "ldap::do_search<core><prepare results>", || {
                    let lres: Result<Vec<_>, _> = res
                        .into_iter()
                        .map(|e| {
                            // dn is uuid=
                            let dn = format!(
                                "uuid={},{}",
                                e.get_uuid().to_hyphenated_ref(),
                                self.basedn
                            );
                            // all others attrs are converted via the protoentry, which we'll disassemble
                            let pe = e.to_pe(au, &mut idm_read.qs_read)?;

                            let attributes: Vec<_> = pe
                                .attrs
                                .into_iter()
                                .map(|(k, vs)| LdapPartialAttribute { atype: k, vals: vs })
                                .collect();

                            Ok(sr.gen_result_entry(LdapSearchResultEntry { dn, attributes }))
                        })
                        .chain(iter::once(Ok(sr.gen_success())))
                        .collect();
                    lres
                });

                let lres = lres.map_err(|e| {
                    ladmin_error!(au, "entry resolve failure {:?}", e);
                    e
                })?;

                Ok(LdapResponseState::MultiPartResponse(lres))
            })
        }
    }

    pub fn do_op(
        &self,
        au: &mut AuditScope,
        idms: &IdmServer,
        server_op: ServerOps,
        uat: Option<LdapBoundToken>,
        eventid: &Uuid,
    ) -> Result<LdapResponseState, OperationError> {
        match server_op {
            ServerOps::SimpleBind(sbr) => {
                let mut idm_write = idms.write();

                let target_uuid: Uuid = if sbr.dn == "" && sbr.pw == "" {
                    UUID_ANONYMOUS.clone()
                } else {
                    idm_write
                        .qs_read
                        .name_to_uuid(au, sbr.dn.as_str())
                        .map_err(|e| {
                            ladmin_info!(au, "Error resolving id to target {:?}", e);
                            e
                        })?
                };

                let ct = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Clock failure!");

                let lae = LdapAuthEvent::from_parts(au, target_uuid, sbr.pw.to_string())?;
                idm_write
                    .auth_ldap(au, lae, ct)
                    .and_then(|r| idm_write.commit(au).map(|_| r))
                    .map(|r| match r {
                        Some(lbt) => LdapResponseState::Bind(lbt, sbr.gen_success()),
                        None => LdapResponseState::Respond(sbr.gen_invalid_cred()),
                    })
            }
            ServerOps::Search(sr) => match uat {
                Some(u) => self.do_search(au, idms, sr, u),
                None => Ok(LdapResponseState::Respond(sr.gen_operror(
                    format!("Unbound Connection {:?}", &eventid).as_str(),
                ))),
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
        output.push_str(",");
    });
    // Remove the last ','
    output.pop();
    output
}
