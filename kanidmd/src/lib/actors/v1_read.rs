use tokio::sync::mpsc::UnboundedSender as Sender;

use std::sync::Arc;

use crate::audit::AuditScope;

use crate::event::{AuthEvent, AuthResult, SearchEvent, SearchResult, WhoamiResult};
use crate::idm::event::{
    CredentialStatusEvent, RadiusAuthTokenEvent, UnixGroupTokenEvent, UnixUserAuthEvent,
    UnixUserTokenEvent,
};
use crate::value::PartialValue;
use kanidm_proto::v1::{OperationError, RadiusAuthToken};

use crate::filter::{Filter, FilterInvalid};
use crate::idm::server::IdmServer;
use crate::ldap::{LdapBoundToken, LdapResponseState, LdapServer};
use crate::server::{QueryServer, QueryServerTransaction};

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::{
    AuthRequest, CredentialStatus, SearchRequest, SearchResponse, UnixGroupToken, UnixUserToken,
    UserAuthToken, WhoamiResponse,
};

use std::time::SystemTime;
use uuid::Uuid;

use ldap3_server::simple::*;
use std::convert::TryFrom;

// These are used when the request (IE Get) has no intrising request
// type. Additionally, they are used in some requests where we need
// to supplement extra server state (IE userauthtokens) to a request.
//
// Generally we don't need to have the responses here because they are
// part of the protocol.

pub struct WhoamiMessage {
    pub uat: Option<UserAuthToken>,
    pub eventid: Uuid,
}

#[derive(Debug)]
pub struct AuthMessage {
    pub sessionid: Option<Uuid>,
    pub req: AuthRequest,
    pub eventid: Uuid,
}

impl AuthMessage {
    pub fn new(req: AuthRequest, sessionid: Option<Uuid>, eventid: Uuid) -> Self {
        AuthMessage {
            sessionid,
            req,
            eventid,
        }
    }
}

pub struct SearchMessage {
    pub uat: Option<UserAuthToken>,
    pub req: SearchRequest,
    pub eventid: Uuid,
}

impl SearchMessage {
    pub fn new(uat: Option<UserAuthToken>, req: SearchRequest, eventid: Uuid) -> Self {
        SearchMessage { uat, req, eventid }
    }
}

pub struct InternalSearchMessage {
    pub uat: Option<UserAuthToken>,
    pub filter: Filter<FilterInvalid>,
    pub attrs: Option<Vec<String>>,
    pub eventid: Uuid,
}

pub struct InternalSearchRecycledMessage {
    pub uat: Option<UserAuthToken>,
    pub filter: Filter<FilterInvalid>,
    pub attrs: Option<Vec<String>>,
    pub eventid: Uuid,
}

pub struct InternalRadiusReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub eventid: Uuid,
}

pub struct InternalRadiusTokenReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub eventid: Uuid,
}

pub struct InternalUnixUserTokenReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub eventid: Uuid,
}

pub struct InternalUnixGroupTokenReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub eventid: Uuid,
}

pub struct InternalSshKeyReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub eventid: Uuid,
}

pub struct InternalSshKeyTagReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub tag: String,
    pub eventid: Uuid,
}

pub struct IdmAccountUnixAuthMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub cred: String,
    pub eventid: Uuid,
}

pub struct IdmCredentialStatusMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub eventid: Uuid,
}

pub struct LdapRequestMessage {
    pub eventid: Uuid,
    pub protomsg: LdapMsg,
    pub uat: Option<LdapBoundToken>,
}

// ===========================================================

pub struct QueryServerReadV1 {
    log: Sender<AuditScope>,
    log_level: Option<u32>,
    qs: QueryServer,
    idms: Arc<IdmServer>,
    ldap: Arc<LdapServer>,
}

impl QueryServerReadV1 {
    pub fn new(
        log: Sender<AuditScope>,
        log_level: Option<u32>,
        qs: QueryServer,
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
    ) -> Self {
        info!("Starting query server v1 worker ...");
        QueryServerReadV1 {
            log,
            log_level,
            qs,
            idms,
            ldap,
        }
    }

    pub fn start_static(
        log: Sender<AuditScope>,
        log_level: Option<u32>,
        query_server: QueryServer,
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
    ) -> &'static Self {
        let x = Box::new(QueryServerReadV1::new(
            log,
            log_level,
            query_server,
            idms,
            ldap,
        ));

        let x_ref = Box::leak(x);
        &(*x_ref)
    }

    // The server only recieves "Message" structures, which
    // are whole self contained DB operations with all parsing
    // required complete. We still need to do certain validation steps, but
    // at this point our just is just to route to do_<action>

    pub async fn handle_search(
        &self,
        msg: SearchMessage,
    ) -> Result<SearchResponse, OperationError> {
        let mut audit = AuditScope::new("search", msg.eventid, self.log_level);
        // Begin a read
        let qs_read = self.qs.read_async().await;
        let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<SearchMessage>", || {
            // Make an event from the request
            let srch = match SearchEvent::from_message(&mut audit, &msg, &qs_read) {
                Ok(s) => s,
                Err(e) => {
                    ladmin_error!(audit, "Failed to begin search: {:?}", e);
                    return Err(e);
                }
            };

            ltrace!(audit, "Begin event {:?}", srch);

            match qs_read.search_ext(&mut audit, &srch) {
                Ok(entries) => {
                    SearchResult::new(&mut audit, &qs_read, &entries).map(|ok_sr| ok_sr.response())
                }
                Err(e) => Err(e),
            }
        });
        // At the end of the event we send it for logging.
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_auth(&self, msg: AuthMessage) -> Result<AuthResult, OperationError> {
        // This is probably the first function that really implements logic
        // "on top" of the db server concept. In this case we check if
        // the credentials provided is sufficient to say if someone is
        // "authenticated" or not.
        let mut audit = AuditScope::new("auth", msg.eventid, self.log_level);
        let mut idm_write = self.idms.write_async().await;
        // let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<AuthMessage>", || {
        lsecurity!(audit, "Begin auth event {:?}", msg);

        // Destructure it.
        // Convert the AuthRequest to an AuthEvent that the idm server
        // can use.
        let ae = AuthEvent::from_message(msg).map_err(|e| {
            ladmin_error!(audit, "Failed to parse AuthEvent -> {:?}", e);
            e
        })?;

        let ct = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                ladmin_error!(audit, "Clock Error -> {:?}", e);
                OperationError::InvalidState
            })?;

        // Trigger a session clean *before* we take any auth steps.
        // It's important to do this before to ensure that timeouts on
        // the session are enforced.
        idm_write.expire_auth_sessions(ct).await;

        // Generally things like auth denied are in Ok() msgs
        // so true errors should always trigger a rollback.
        let res = idm_write
            .auth(&mut audit, &ae, ct)
            .await
            .and_then(|r| idm_write.commit(&mut audit).map(|_| r));

        lsecurity!(audit, "Sending auth result -> {:?}", res);
        // Build the result.
        // r.map(|r| r.response())
        // r
        // });
        // At the end of the event we send it for logging.
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_whoami(
        &self,
        msg: WhoamiMessage,
    ) -> Result<WhoamiResponse, OperationError> {
        let mut audit = AuditScope::new("whoami", msg.eventid, self.log_level);
        // TODO #62: Move this to IdmServer!!!
        // Begin a read
        let qs_read = self.qs.read_async().await;
        let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<WhoamiMessage>", || {
            // Make an event from the whoami request. This will process the event and
            // generate a selfuuid search.
            //
            // This current handles the unauthenticated check, and will
            // trigger the failure, but if we can manage to work out async
            // then move this to core.rs, and don't allow Option<UAT> to get
            // this far.
            let uat = msg.uat.clone().ok_or(OperationError::NotAuthenticated)?;

            let srch =
                match SearchEvent::from_whoami_request(&mut audit, msg.uat.as_ref(), &qs_read) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin whoami: {:?}", e);
                        return Err(e);
                    }
                };

            ltrace!(audit, "Begin event {:?}", srch);

            match qs_read.search_ext(&mut audit, &srch) {
                Ok(mut entries) => {
                    // assert there is only one ...
                    match entries.len() {
                        0 => Err(OperationError::NoMatchingEntries),
                        1 => {
                            #[allow(clippy::expect_used)]
                            let e = entries.pop().expect("Entry length mismatch!!!");
                            // Now convert to a response, and return
                            WhoamiResult::new(&mut audit, &qs_read, &e, uat)
                                .map(|ok_wr| ok_wr.response())
                        }
                        // Somehow we matched multiple, which should be impossible.
                        _ => Err(OperationError::InvalidState),
                    }
                }
                // Something else went wrong ...
                Err(e) => Err(e),
            }
        });
        // Should we log the final result?
        // At the end of the event we send it for logging.
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalsearch(
        &self,
        msg: InternalSearchMessage,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let mut audit = AuditScope::new("internal_search_message", msg.eventid, self.log_level);
        let qs_read = self.qs.read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSearchMessage>",
            || {
                // Make an event from the request
                let srch = match SearchEvent::from_internal_message(&mut audit, msg, &qs_read) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin internal api search: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                match qs_read.search_ext(&mut audit, &srch) {
                    Ok(entries) => SearchResult::new(&mut audit, &qs_read, &entries)
                        .map(|ok_sr| ok_sr.into_proto_array()),
                    Err(e) => Err(e),
                }
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalsearchrecycled(
        &self,
        msg: InternalSearchRecycledMessage,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let mut audit = AuditScope::new(
            "internal_search_recycle_message",
            msg.eventid,
            self.log_level,
        );
        let qs_read = self.qs.read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSearchRecycledMessage>",
            || {
                // Make an event from the request
                let srch =
                    match SearchEvent::from_internal_recycle_message(&mut audit, msg, &qs_read) {
                        Ok(s) => s,
                        Err(e) => {
                            ladmin_error!(audit, "Failed to begin recycled search: {:?}", e);
                            return Err(e);
                        }
                    };

                ltrace!(audit, "Begin event {:?}", srch);

                match qs_read.search_ext(&mut audit, &srch) {
                    Ok(entries) => SearchResult::new(&mut audit, &qs_read, &entries)
                        .map(|ok_sr| ok_sr.into_proto_array()),
                    Err(e) => Err(e),
                }
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalradiusread(
        &self,
        msg: InternalRadiusReadMessage,
    ) -> Result<Option<String>, OperationError> {
        let mut audit =
            AuditScope::new("internal_radius_read_message", msg.eventid, self.log_level);
        let qs_read = self.qs.read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalRadiusReadMessage>",
            || {
                let target_uuid = qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let srch = match SearchEvent::from_target_uuid_request(
                    &mut audit,
                    msg.uat.as_ref(),
                    target_uuid,
                    &qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin radius read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                // We have to use search_ext to guarantee acs was applied.
                match qs_read.search_ext(&mut audit, &srch) {
                    Ok(mut entries) => {
                        let r = entries
                            .pop()
                            // From the entry, turn it into the value
                            .and_then(|e| {
                                e.get_ava_single("radius_secret")
                                    .and_then(|v| v.get_radius_secret().map(|s| s.to_string()))
                            });
                        Ok(r)
                    }
                    Err(e) => Err(e),
                }
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalradiustokenread(
        &self,
        msg: InternalRadiusTokenReadMessage,
    ) -> Result<RadiusAuthToken, OperationError> {
        let mut audit = AuditScope::new(
            "internal_radius_token_read_message",
            msg.eventid,
            self.log_level,
        );
        let mut idm_read = self.idms.proxy_read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalRadiusTokenReadMessage>",
            || {
                let target_uuid = idm_read
                    .qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let rate = match RadiusAuthTokenEvent::from_parts(
                    &mut audit,
                    &idm_read.qs_read,
                    msg.uat.as_ref(),
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin radius token read: {:?}", e);
                        return Err(e);
                    }
                };

                let ct = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|e| {
                        ladmin_error!(audit, "Clock Error -> {:?}", e);
                        OperationError::InvalidState
                    })?;

                ltrace!(audit, "Begin event {:?}", rate);

                idm_read.get_radiusauthtoken(&mut audit, &rate, ct)
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalunixusertokenread(
        &self,
        msg: InternalUnixUserTokenReadMessage,
    ) -> Result<UnixUserToken, OperationError> {
        let mut audit = AuditScope::new(
            "internal_unix_token_read_message",
            msg.eventid,
            self.log_level,
        );
        let mut idm_read = self.idms.proxy_read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalUnixUserTokenReadMessage>",
            || {
                let target_uuid = idm_read
                    .qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_info!(
                            &mut audit,
                            "Error resolving {} as gidnumber continuing ... {:?}",
                            msg.uuid_or_name,
                            e
                        );
                        e
                    })?;

                // Make an event from the request
                let rate = match UnixUserTokenEvent::from_parts(
                    &mut audit,
                    &idm_read.qs_read,
                    msg.uat.as_ref(),
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin unix token read: {:?}", e);
                        return Err(e);
                    }
                };

                let ct = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|e| {
                        ladmin_error!(audit, "Clock Error -> {:?}", e);
                        OperationError::InvalidState
                    })?;

                ltrace!(audit, "Begin event {:?}", rate);

                idm_read.get_unixusertoken(&mut audit, &rate, ct)
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalunixgrouptokenread(
        &self,
        msg: InternalUnixGroupTokenReadMessage,
    ) -> Result<UnixGroupToken, OperationError> {
        let mut audit = AuditScope::new(
            "internal_unixgroup_token_read_message",
            msg.eventid,
            self.log_level,
        );
        let mut idm_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalUnixGroupTokenReadMessage>",
            || {
                let target_uuid = idm_read
                    .qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_info!(&mut audit, "Error resolving as gidnumber continuing ...");
                        e
                    })?;

                // Make an event from the request
                let rate = match UnixGroupTokenEvent::from_parts(
                    &mut audit,
                    &idm_read.qs_read,
                    msg.uat.as_ref(),
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin unix group token read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", rate);

                idm_read.get_unixgrouptoken(&mut audit, &rate)
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalsshkeyread(
        &self,
        msg: InternalSshKeyReadMessage,
    ) -> Result<Vec<String>, OperationError> {
        let mut audit =
            AuditScope::new("internal_sshkey_read_message", msg.eventid, self.log_level);
        let qs_read = self.qs.read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSshKeyReadMessage>",
            || {
                let target_uuid = qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let srch = match SearchEvent::from_target_uuid_request(
                    &mut audit,
                    msg.uat.as_ref(),
                    target_uuid,
                    &qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin ssh key read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                match qs_read.search_ext(&mut audit, &srch) {
                    Ok(mut entries) => {
                        let r = entries
                            .pop()
                            // get the first entry
                            .and_then(|e| {
                                // From the entry, turn it into the value
                                e.get_ava_iter_sshpubkeys("ssh_publickey")
                                    .map(|i| i.map(|s| s.to_string()).collect())
                            })
                            .unwrap_or_else(|| {
                                // No matching entry? Return none.
                                Vec::new()
                            });
                        Ok(r)
                    }
                    Err(e) => Err(e),
                }
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internalsshkeytagread(
        &self,
        msg: InternalSshKeyTagReadMessage,
    ) -> Result<Option<String>, OperationError> {
        let InternalSshKeyTagReadMessage {
            uat,
            uuid_or_name,
            tag,
            eventid,
        } = msg;
        let mut audit =
            AuditScope::new("internal_sshkey_tag_read_message", eventid, self.log_level);
        let qs_read = self.qs.read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSshKeyTagReadMessage>",
            || {
                let target_uuid = qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_info!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let srch = match SearchEvent::from_target_uuid_request(
                    &mut audit,
                    uat.as_ref(),
                    target_uuid,
                    &qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin sshkey tag read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                match qs_read.search_ext(&mut audit, &srch) {
                    Ok(mut entries) => {
                        let r = entries
                            .pop()
                            // get the first entry
                            .map(|e| {
                                // From the entry, turn it into the value
                                e.get_ava_set("ssh_publickey").and_then(|vs| {
                                    // Get the one tagged value
                                    let pv = PartialValue::new_sshkey_tag(tag);
                                    vs.get(&pv)
                                        // Now turn that value to a pub key.
                                        .and_then(|v| v.get_sshkey())
                                        .map(|s| s.to_string())
                                })
                            })
                            .unwrap_or_else(|| {
                                // No matching entry? Return none.
                                None
                            });
                        Ok(r)
                    }
                    Err(e) => Err(e),
                }
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_idmaccountunixauth(
        &self,
        msg: IdmAccountUnixAuthMessage,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        let mut audit = AuditScope::new("idm_account_unix_auth", msg.eventid, self.log_level);
        let mut idm_write = self.idms.write_async().await;
        // let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<IdmAccountUnixAuthMessage>", || {
        // resolve the id
        let target_uuid = idm_write
            .qs_read
            .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
            .map_err(|e| {
                ladmin_info!(&mut audit, "Error resolving as gidnumber continuing ...");
                e
            })?;
        // Make an event from the request
        let uuae = match UnixUserAuthEvent::from_parts(
            &mut audit,
            &idm_write.qs_read,
            msg.uat.as_ref(),
            target_uuid,
            msg.cred,
        ) {
            Ok(s) => s,
            Err(e) => {
                ladmin_error!(audit, "Failed to begin unix auth: {:?}", e);
                return Err(e);
            }
        };

        lsecurity!(audit, "Begin event {:?}", uuae);

        let ct = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                ladmin_error!(audit, "Clock Error -> {:?}", e);
                OperationError::InvalidState
            })?;

        let res = idm_write
            .auth_unix(&mut audit, &uuae, ct)
            .await
            .and_then(|r| idm_write.commit(&mut audit).map(|_| r));

        lsecurity!(audit, "Sending result -> {:?}", res);
        // res
        // });
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_idmcredentialstatus(
        &self,
        msg: IdmCredentialStatusMessage,
    ) -> Result<CredentialStatus, OperationError> {
        let mut audit =
            AuditScope::new("idm_credential_status_message", msg.eventid, self.log_level);
        let mut idm_read = self.idms.proxy_read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<IdmCredentialStatusMessage>",
            || {
                let target_uuid = idm_read
                    .qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let cse = match CredentialStatusEvent::from_parts(
                    &mut audit,
                    &idm_read.qs_read,
                    msg.uat.as_ref(),
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin credential status read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", cse);

                idm_read.get_credentialstatus(&mut audit, &cse)
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_ldaprequest(&self, msg: LdapRequestMessage) -> Option<LdapResponseState> {
        let LdapRequestMessage {
            eventid,
            protomsg,
            uat,
        } = msg;
        let mut audit = AuditScope::new("ldap_request_message", eventid, self.log_level);

        /*
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<LdapRequestMessage>",
            || {
        */
        let res = match ServerOps::try_from(protomsg) {
            Ok(server_op) => self
                .ldap
                .do_op(&mut audit, &self.idms, server_op, uat, &eventid)
                .await
                .unwrap_or_else(|e| {
                    ladmin_error!(&mut audit, "do_op failed -> {:?}", e);
                    LdapResponseState::Disconnect(DisconnectionNotice::gen(
                        LdapResultCode::Other,
                        format!("Internal Server Error {:?}", &eventid).as_str(),
                    ))
                }),
            Err(_) => LdapResponseState::Disconnect(DisconnectionNotice::gen(
                LdapResultCode::ProtocolError,
                format!("Invalid Request {:?}", &eventid).as_str(),
            )),
        };
        /*
            }
        );
        */
        if self.log.send(audit).is_err() {
            error!("Unable to commit log -> {:?}", &eventid);
            Some(LdapResponseState::Disconnect(DisconnectionNotice::gen(
                LdapResultCode::Other,
                format!("Internal Server Error {:?}", &eventid).as_str(),
            )))
        } else {
            Some(res)
        }
    }
}
