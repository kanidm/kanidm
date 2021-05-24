use tokio::sync::mpsc::UnboundedSender as Sender;

use std::sync::Arc;

use crate::prelude::*;

use crate::event::{AuthEvent, AuthResult, SearchEvent, SearchResult, WhoamiResult};
use crate::idm::event::{
    CredentialStatusEvent, RadiusAuthTokenEvent, UnixGroupTokenEvent, UnixUserAuthEvent,
    UnixUserTokenEvent,
};
use crate::value::PartialValue;
use kanidm_proto::v1::{OperationError, RadiusAuthToken};

use crate::filter::{Filter, FilterInvalid};
use crate::idm::server::{IdmServer, IdmServerTransaction};
use crate::ldap::{LdapBoundToken, LdapResponseState, LdapServer};

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::{
    AuthRequest, CredentialStatus, SearchRequest, SearchResponse, UnixGroupToken, UnixUserToken,
    WhoamiResponse,
};

use uuid::Uuid;

use ldap3_server::simple::*;
use std::convert::TryFrom;

// ===========================================================

pub struct QueryServerReadV1 {
    log: Sender<AuditScope>,
    log_level: Option<u32>,
    idms: Arc<IdmServer>,
    ldap: Arc<LdapServer>,
}

impl QueryServerReadV1 {
    pub fn new(
        log: Sender<AuditScope>,
        log_level: Option<u32>,
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
    ) -> Self {
        info!("Starting query server v1 worker ...");
        QueryServerReadV1 {
            log,
            log_level,
            idms,
            ldap,
        }
    }

    pub fn start_static(
        log: Sender<AuditScope>,
        log_level: Option<u32>,
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
    ) -> &'static Self {
        let x = Box::new(QueryServerReadV1::new(log, log_level, idms, ldap));

        let x_ref = Box::leak(x);
        &(*x_ref)
    }

    // The server only recieves "Message" structures, which
    // are whole self contained DB operations with all parsing
    // required complete. We still need to do certain validation steps, but
    // at this point our just is just to route to do_<action>

    pub async fn handle_search(
        &self,
        uat: Option<String>,
        req: SearchRequest,
        eventid: Uuid,
    ) -> Result<SearchResponse, OperationError> {
        let mut audit = AuditScope::new("search", eventid, self.log_level);
        // Begin a read
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<SearchMessage>", || {
            let ident = idms_prox_read
                .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                .map_err(|e| {
                    ladmin_error!(audit, "Invalid identity: {:?}", e);
                    e
                })?;

            // Make an event from the request
            let srch =
                match SearchEvent::from_message(&mut audit, ident, &req, &idms_prox_read.qs_read) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin search: {:?}", e);
                        return Err(e);
                    }
                };

            ltrace!(audit, "Begin event {:?}", srch);

            match idms_prox_read.qs_read.search_ext(&mut audit, &srch) {
                Ok(entries) => SearchResult::new(&mut audit, &idms_prox_read.qs_read, &entries)
                    .map(|ok_sr| ok_sr.response()),
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

    pub async fn handle_auth(
        &self,
        sessionid: Option<Uuid>,
        req: AuthRequest,
        eventid: Uuid,
    ) -> Result<AuthResult, OperationError> {
        // This is probably the first function that really implements logic
        // "on top" of the db server concept. In this case we check if
        // the credentials provided is sufficient to say if someone is
        // "authenticated" or not.
        let mut audit = AuditScope::new("auth", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idm_auth = self.idms.auth_async().await;
        // let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<AuthMessage>", || {
        lsecurity!(audit, "Begin auth event {:?} {:?}", sessionid, req);

        // Destructure it.
        // Convert the AuthRequest to an AuthEvent that the idm server
        // can use.
        let ae = AuthEvent::from_message(sessionid, req).map_err(|e| {
            ladmin_error!(audit, "Failed to parse AuthEvent -> {:?}", e);
            e
        })?;

        // Trigger a session clean *before* we take any auth steps.
        // It's important to do this before to ensure that timeouts on
        // the session are enforced.
        idm_auth.expire_auth_sessions(ct).await;

        // Generally things like auth denied are in Ok() msgs
        // so true errors should always trigger a rollback.
        let res = idm_auth
            .auth(&mut audit, &ae, ct)
            .await
            .and_then(|r| idm_auth.commit(&mut audit).map(|_| r));

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
        uat: Option<String>,
        eventid: Uuid,
    ) -> Result<WhoamiResponse, OperationError> {
        let mut audit = AuditScope::new("whoami", eventid, self.log_level);
        // TODO #62: Move this to IdmServer!!!
        // Begin a read
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<WhoamiMessage>", || {
            // Make an event from the whoami request. This will process the event and
            // generate a selfuuid search.
            //
            // This current handles the unauthenticated check, and will
            // trigger the failure, but if we can manage to work out async
            // then move this to core.rs, and don't allow Option<UAT> to get
            // this far.
            let (uat, ident) = idms_prox_read
                .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                .and_then(|uat| {
                    idms_prox_read
                        .process_uat_to_identity(&mut audit, &uat)
                        .map(|i| (uat, i))
                })
                .map_err(|e| {
                    ladmin_error!(audit, "Invalid identity: {:?}", e);
                    e
                })?;

            let srch = match SearchEvent::from_whoami_request(
                &mut audit,
                ident,
                &idms_prox_read.qs_read,
            ) {
                Ok(s) => s,
                Err(e) => {
                    ladmin_error!(audit, "Failed to begin whoami: {:?}", e);
                    return Err(e);
                }
            };

            ltrace!(audit, "Begin event {:?}", srch);

            match idms_prox_read.qs_read.search_ext(&mut audit, &srch) {
                Ok(mut entries) => {
                    // assert there is only one ...
                    match entries.len() {
                        0 => Err(OperationError::NoMatchingEntries),
                        1 => {
                            #[allow(clippy::expect_used)]
                            let e = entries.pop().expect("Entry length mismatch!!!");
                            // Now convert to a response, and return
                            WhoamiResult::new(&mut audit, &idms_prox_read.qs_read, &e, uat)
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
        uat: Option<String>,
        filter: Filter<FilterInvalid>,
        attrs: Option<Vec<String>>,
        eventid: Uuid,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let mut audit = AuditScope::new("internal_search_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSearchMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;
                // Make an event from the request
                let srch = match SearchEvent::from_internal_message(
                    &mut audit,
                    ident,
                    &filter,
                    attrs.as_deref(),
                    &idms_prox_read.qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin internal api search: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                match idms_prox_read.qs_read.search_ext(&mut audit, &srch) {
                    Ok(entries) => SearchResult::new(&mut audit, &idms_prox_read.qs_read, &entries)
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
        uat: Option<String>,
        filter: Filter<FilterInvalid>,
        attrs: Option<Vec<String>>,
        eventid: Uuid,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let mut audit = AuditScope::new("internal_search_recycle_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSearchRecycledMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;
                // Make an event from the request
                let srch = match SearchEvent::from_internal_recycle_message(
                    &mut audit,
                    ident,
                    &filter,
                    attrs.as_deref(),
                    &idms_prox_read.qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin recycled search: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                match idms_prox_read.qs_read.search_ext(&mut audit, &srch) {
                    Ok(entries) => SearchResult::new(&mut audit, &idms_prox_read.qs_read, &entries)
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
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Option<String>, OperationError> {
        let mut audit = AuditScope::new("internal_radius_read_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalRadiusReadMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;

                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let srch = match SearchEvent::from_target_uuid_request(
                    &mut audit,
                    ident,
                    target_uuid,
                    &idms_prox_read.qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin radius read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                // We have to use search_ext to guarantee acs was applied.
                match idms_prox_read.qs_read.search_ext(&mut audit, &srch) {
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
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<RadiusAuthToken, OperationError> {
        let mut audit = AuditScope::new(
            "internal_radius_token_read_message",
            eventid,
            self.log_level,
        );
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalRadiusTokenReadMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;

                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let rate = match RadiusAuthTokenEvent::from_parts(
                    &mut audit,
                    // &idms_prox_read.qs_read,
                    ident,
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin radius token read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", rate);

                idms_prox_read.get_radiusauthtoken(&mut audit, &rate, ct)
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
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<UnixUserToken, OperationError> {
        let mut audit =
            AuditScope::new("internal_unix_token_read_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalUnixUserTokenReadMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;

                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_info!(
                            &mut audit,
                            "Error resolving {} as gidnumber continuing ... {:?}",
                            uuid_or_name,
                            e
                        );
                        e
                    })?;

                // Make an event from the request
                let rate = match UnixUserTokenEvent::from_parts(&mut audit, ident, target_uuid) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin unix token read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", rate);

                idms_prox_read.get_unixusertoken(&mut audit, &rate, ct)
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
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<UnixGroupToken, OperationError> {
        let mut audit = AuditScope::new(
            "internal_unixgroup_token_read_message",
            eventid,
            self.log_level,
        );
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalUnixGroupTokenReadMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;

                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_info!(&mut audit, "Error resolving as gidnumber continuing ...");
                        e
                    })?;

                // Make an event from the request
                let rate = match UnixGroupTokenEvent::from_parts(
                    &mut audit,
                    // &idms_prox_read.qs_read,
                    ident,
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin unix group token read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", rate);

                idms_prox_read.get_unixgrouptoken(&mut audit, &rate)
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
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Vec<String>, OperationError> {
        let mut audit = AuditScope::new("internal_sshkey_read_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSshKeyReadMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;
                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let srch = match SearchEvent::from_target_uuid_request(
                    &mut audit,
                    ident,
                    target_uuid,
                    &idms_prox_read.qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin ssh key read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                match idms_prox_read.qs_read.search_ext(&mut audit, &srch) {
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
        uat: Option<String>,
        uuid_or_name: String,
        tag: String,
        eventid: Uuid,
    ) -> Result<Option<String>, OperationError> {
        let mut audit =
            AuditScope::new("internal_sshkey_tag_read_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<InternalSshKeyTagReadMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;
                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_info!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let srch = match SearchEvent::from_target_uuid_request(
                    &mut audit,
                    ident,
                    target_uuid,
                    &idms_prox_read.qs_read,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin sshkey tag read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", srch);

                match idms_prox_read.qs_read.search_ext(&mut audit, &srch) {
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
        uat: Option<String>,
        uuid_or_name: String,
        cred: String,
        eventid: Uuid,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        let mut audit = AuditScope::new("idm_account_unix_auth", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idm_auth = self.idms.auth_async().await;
        // let res = lperf_op_segment!(&mut audit, "actors::v1_read::handle<IdmAccountUnixAuthMessage>", || {
        // resolve the id
        let ident = idm_auth
            .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
            .and_then(|uat| idm_auth.process_uat_to_identity(&mut audit, &uat))
            .map_err(|e| {
                ladmin_error!(audit, "Invalid identity: {:?}", e);
                e
            })?;

        let target_uuid = idm_auth
            .qs_read
            .name_to_uuid(&mut audit, uuid_or_name.as_str())
            .map_err(|e| {
                ladmin_info!(&mut audit, "Error resolving as gidnumber continuing ...");
                e
            })?;
        // Make an event from the request
        let uuae = match UnixUserAuthEvent::from_parts(&mut audit, ident, target_uuid, cred) {
            Ok(s) => s,
            Err(e) => {
                ladmin_error!(audit, "Failed to begin unix auth: {:?}", e);
                return Err(e);
            }
        };

        lsecurity!(audit, "Begin event {:?}", uuae);

        let res = idm_auth
            .auth_unix(&mut audit, &uuae, ct)
            .await
            .and_then(|r| idm_auth.commit(&mut audit).map(|_| r));

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
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<CredentialStatus, OperationError> {
        let mut audit = AuditScope::new("idm_credential_status_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;

        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_read::handle<IdmCredentialStatusMessage>",
            || {
                let ident = idms_prox_read
                    .validate_and_parse_uat(&mut audit, uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&mut audit, &uat))
                    .map_err(|e| {
                        ladmin_error!(audit, "Invalid identity: {:?}", e);
                        e
                    })?;
                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(&mut audit, "Error resolving id to target");
                        e
                    })?;

                // Make an event from the request
                let cse = match CredentialStatusEvent::from_parts(
                    &mut audit,
                    // &idms_prox_read.qs_read,
                    ident,
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin credential status read: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin event {:?}", cse);

                idms_prox_read.get_credentialstatus(&mut audit, &cse)
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_ldaprequest(
        &self,
        eventid: Uuid,
        protomsg: LdapMsg,
        uat: Option<LdapBoundToken>,
    ) -> Option<LdapResponseState> {
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
