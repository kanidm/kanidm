use crate::audit::AuditScope;
use crate::constants::UUID_ANONYMOUS;
use crate::idm::event::LdapAuthEvent;
use crate::idm::server::IdmServer;
use crate::server::QueryServerTransaction;
use kanidm_proto::v1::OperationError;
use ldap3_server::simple::*;
use std::time::SystemTime;
use uuid::Uuid;

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

pub fn ldap_do_op(
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
        ServerOps::Search(sr) => {
            // self.do_search(&sr)
            match uat {
                Some(u) => unimplemented!(),
                None => Ok(LdapResponseState::Respond(sr.gen_operror(
                    format!("Unbound Connection {:?}", &eventid).as_str(),
                ))),
            }
        }
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
