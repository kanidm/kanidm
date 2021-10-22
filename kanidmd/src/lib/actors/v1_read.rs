use tracing::{error, info, instrument, trace};

use chrono::{DateTime, SecondsFormat, Utc};
use std::sync::Arc;

use crate::prelude::*;

use crate::be::BackendTransaction;

use crate::event::{
    AuthEvent, AuthResult, OnlineBackupEvent, SearchEvent, SearchResult, WhoamiResult,
};
use crate::idm::event::{
    CredentialStatusEvent, RadiusAuthTokenEvent, ReadBackupCodeEvent, UnixGroupTokenEvent,
    UnixUserAuthEvent, UnixUserTokenEvent,
};
use kanidm_proto::v1::{BackupCodesView, OperationError, RadiusAuthToken};

use crate::filter::{Filter, FilterInvalid};
use crate::idm::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AuthorisationRequest, AuthorisePermitSuccess, ConsentRequest, Oauth2Error,
};
use crate::idm::server::{IdmServer, IdmServerTransaction};
use crate::ldap::{LdapBoundToken, LdapResponseState, LdapServer};

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::{
    AuthRequest, CredentialStatus, SearchRequest, SearchResponse, UnixGroupToken, UnixUserToken,
    WhoamiResponse,
};

use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use ldap3_server::simple::*;
use std::convert::TryFrom;

// ===========================================================

pub struct QueryServerReadV1 {
    pub log_level: Option<u32>,
    idms: Arc<IdmServer>,
    ldap: Arc<LdapServer>,
}

impl QueryServerReadV1 {
    pub fn new(log_level: Option<u32>, idms: Arc<IdmServer>, ldap: Arc<LdapServer>) -> Self {
        info!("Starting query server v1 worker ...");
        QueryServerReadV1 {
            log_level,
            idms,
            ldap,
        }
    }

    pub fn start_static(
        log_level: Option<u32>,
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
    ) -> &'static Self {
        let x = Box::new(QueryServerReadV1::new(log_level, idms, ldap));

        let x_ref = Box::leak(x);
        &(*x_ref)
    }

    // The server only recieves "Message" structures, which
    // are whole self contained DB operations with all parsing
    // required complete. We still need to do certain validation steps, but
    // at this point our just is just to route to do_<action>

    // ! For uuid, we should deprecate `RequestExtensions::new_eventid` and just manually call
    // ! `Uuid::new_v4().to_hyphenated().to_string()` instead of keeping a `Uuid` around.
    // ! Ideally, this function takes &self, uat, req, and then a `uuid` argument that is a `&str` of the hyphenated uuid.
    // ! Then we just don't skip uuid, and we don't have to do the custom `fields(..)` stuff in this macro call.
    #[instrument(
        level = "trace",
        name = "search",
        skip(self, uat, req, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_search(
        &self,
        uat: Option<String>,
        req: SearchRequest,
        eventid: Uuid,
    ) -> Result<SearchResponse, OperationError> {
        // Begin a read
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        // ! NOTICE: The inner function contains a short-circuiting `return`, which is only exits the closure.
        // ! If we removed the `lperf_op_segment` and kept the inside, this would short circuit before logging `audit`.
        // ! However, since we immediately return `res` after logging `audit`, and we should be removing the lperf stuff
        // ! and the logging of `audit` at the same time, it is ok if the inner code short circuits the whole function because
        // ! there is no work to be done afterwards.
        // ! However, if we want to do work after `res` is calculated, we need to pass `spanned` a closure instead of a block
        // ! in order to not short-circuit the entire function.
        let res = spanned!("actors::v1_read::handle<SearchMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(?e, "Invalid identity");
                    e
                })?;

            // Make an event from the request
            let search =
                SearchEvent::from_message(ident, &req, &idms_prox_read.qs_read).map_err(|e| {
                    admin_error!(?e, "Failed to begin search");
                    e
                })?;

            trace!(?search, "Begin event");

            let entries = idms_prox_read.qs_read.search_ext(&search)?;

            SearchResult::new(&idms_prox_read.qs_read, &entries).map(SearchResult::response)
        });
        res
    }

    // ! TRACING INTEGRATED
    #[instrument(
        level = "trace",
        name = "auth",
        skip(self, sessionid, req, eventid)
        fields(uuid = ?eventid)
    )]
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
        let ct = duration_from_epoch_now();
        let mut idm_auth = self.idms.auth_async().await;
        security_info!(?sessionid, ?req, "Begin auth event");

        // Destructure it.
        // Convert the AuthRequest to an AuthEvent that the idm server
        // can use.
        let ae = AuthEvent::from_message(sessionid, req).map_err(|e| {
            admin_error!(err = ?e, "Failed to parse AuthEvent");
            e
        })?;

        // Trigger a session clean *before* we take any auth steps.
        // It's important to do this before to ensure that timeouts on
        // the session are enforced.
        idm_auth.expire_auth_sessions(ct).await;

        // Generally things like auth denied are in Ok() msgs
        // so true errors should always trigger a rollback.
        let res = idm_auth
            .auth(&ae, ct)
            .await
            .and_then(|r| idm_auth.commit().map(|_| r));

        security_info!(?res, "Sending auth result");

        res
    }

    #[instrument(
        level = "trace",
        name = "online_backup",
        skip(self, msg, outpath, versions)
        fields(uuid = ?msg.eventid)
    )]
    pub async fn handle_online_backup(
        &self,
        msg: OnlineBackupEvent,
        outpath: &str,
        versions: usize,
    ) {
        trace!(eventid = ?msg.eventid, "Begin online backup event");

        let now: DateTime<Utc> = Utc::now();
        let timestamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        let dest_file = format!("{}/backup-{}.json", outpath, timestamp);

        match Path::new(&dest_file).exists() {
            true => {
                error!(
                    "Online backup file {} already exists, will not owerwrite it.",
                    dest_file
                );
            }
            false => {
                let idms_prox_read = self.idms.proxy_read_async().await;
                spanned!("actors::v1_read::handle<OnlineBackupEvent>", {
                    let res = idms_prox_read.qs_read.get_be_txn().backup(&dest_file);

                    match &res {
                        Ok(()) => {
                            info!("Online backup created {} successfully", dest_file);
                        }
                        Err(e) => {
                            error!("Online backup failed to create {}: {:?}", dest_file, e);
                        }
                    }

                    admin_info!(?res, "online backup result");
                });
            }
        }

        // cleanup of maximum backup versions to keep
        let mut backup_file_list: Vec<PathBuf> = Vec::new();
        // pattern to find automatically generated backup files
        let re = match Regex::new(r"^backup-\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\.json$") {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "Failed to parse regexp for online backup files: {:?}",
                    error
                );
                return;
            }
        };

        // get a list of backup files
        match fs::read_dir(outpath) {
            Ok(rd) => {
                for entry in rd {
                    // get PathBuf
                    let pb = entry.unwrap().path();

                    // skip everything that is not a file
                    if !pb.is_file() {
                        continue;
                    }

                    // get the /some/dir/<file_name> of the file
                    let file_name = pb.file_name().unwrap().to_str().unwrap();
                    // check for a online backup file
                    if re.is_match(file_name) {
                        backup_file_list.push(pb.clone());
                    }
                }
            }
            Err(e) => {
                error!("Online backup cleanup error read dir {}: {}", outpath, e);
            }
        }

        // sort it to have items listed old to new
        backup_file_list.sort();

        // Versions: OLD 10.9.8.7.6.5.4.3.2.1 NEW
        //              |----delete----|keep|
        // 10 items, we want to keep the latest 3

        // if we have more files then we want to keep, me do some cleanup
        if backup_file_list.len() > versions {
            let x = backup_file_list.len() - versions;
            info!(
                "Online backup cleanup found {} versions, should keep {}, will remove {}",
                backup_file_list.len(),
                versions,
                x
            );
            backup_file_list.truncate(x);

            // removing files
            for file in backup_file_list {
                debug!("Online backup cleanup: removing {:?}", &file);
                match fs::remove_file(&file) {
                    Ok(_) => {}
                    Err(e) => {
                        error!(
                            "Online backup cleanup failed to remove file {:?}: {:?}",
                            file, e
                        )
                    }
                };
            }
        } else {
            debug!("Online backup cleanup had no files to remove");
        };
    }

    #[instrument(
        level = "trace",
        name = "whoami",
        skip(self, uat, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_whoami(
        &self,
        uat: Option<String>,
        eventid: Uuid,
    ) -> Result<WhoamiResponse, OperationError> {
        // TODO #62: Move this to IdmServer!!!
        // Begin a read
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        // ! NOTICE: The inner function contains a short-circuiting `return`, which is only exits the closure.
        // ! If we removed the `lperf_op_segment` and kept the inside, this would short circuit before logging `audit`.
        // ! However, since we immediately return `res` after logging `audit`, and we should be removing the lperf stuff
        // ! and the logging of `audit` at the same time, it is ok if the inner code short circuits the whole function because
        // ! there is no work to be done afterwards.
        // ! However, if we want to do work after `res` is calculated, we need to pass `spanned` a closure instead of a block
        // ! in order to not short-circuit the entire function.
        let res = spanned!("actors::v1_read::handle<WhoamiMessage>", {
            // Make an event from the whoami request. This will process the event and
            // generate a selfuuid search.
            //
            // This current handles the unauthenticated check, and will
            // trigger the failure, but if we can manage to work out async
            // then move this to core.rs, and don't allow Option<UAT> to get
            // this far.
            let (uat, ident) = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| {
                    idms_prox_read
                        .process_uat_to_identity(&uat, ct)
                        .map(|i| (uat, i))
                })
                .map_err(|e| {
                    admin_error!(?e, "Invalid identity");
                    e
                })?;

            let srch =
                SearchEvent::from_whoami_request(ident, &idms_prox_read.qs_read).map_err(|e| {
                    admin_error!(?e, "Failed to begin whoami");
                    e
                })?;

            trace!(search = ?srch, "Begin event");

            let mut entries = idms_prox_read.qs_read.search_ext(&srch)?;

            match entries.pop() {
                Some(e) if entries.is_empty() => {
                    WhoamiResult::new(&idms_prox_read.qs_read, &e, uat).map(WhoamiResult::response)
                }
                Some(_) => Err(OperationError::InvalidState), // Somehow matched multiple entries...
                _ => Err(OperationError::NoMatchingEntries),
            }
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "internalsearch",
        skip(self, uat, filter, attrs, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsearch(
        &self,
        uat: Option<String>,
        filter: Filter<FilterInvalid>,
        attrs: Option<Vec<String>>,
        eventid: Uuid,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<InternalSearchMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;
            // Make an event from the request
            let srch = match SearchEvent::from_internal_message(
                ident,
                &filter,
                attrs.as_deref(),
                &idms_prox_read.qs_read,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to begin internal api search: {:?}", e);
                    return Err(e);
                }
            };

            trace!(?srch, "Begin event");

            match idms_prox_read.qs_read.search_ext(&srch) {
                Ok(entries) => SearchResult::new(&idms_prox_read.qs_read, &entries)
                    .map(|ok_sr| ok_sr.into_proto_array()),
                Err(e) => Err(e),
            }
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "internalsearchrecycled",
        skip(self, uat, filter, attrs, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsearchrecycled(
        &self,
        uat: Option<String>,
        filter: Filter<FilterInvalid>,
        attrs: Option<Vec<String>>,
        eventid: Uuid,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;

        let res = spanned!("actors::v1_read::handle<InternalSearchRecycledMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;
            // Make an event from the request
            let srch = match SearchEvent::from_internal_recycle_message(
                ident,
                &filter,
                attrs.as_deref(),
                &idms_prox_read.qs_read,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to begin recycled search: {:?}", e);
                    return Err(e);
                }
            };

            trace!(?srch, "Begin event");

            match idms_prox_read.qs_read.search_ext(&srch) {
                Ok(entries) => SearchResult::new(&idms_prox_read.qs_read, &entries)
                    .map(|ok_sr| ok_sr.into_proto_array()),
                Err(e) => Err(e),
            }
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "internalradiusread",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalradiusread(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Option<String>, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<InternalRadiusReadMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;

            let target_uuid = idms_prox_read
                .qs_read
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!("Error resolving id to target");
                    e
                })?;

            // Make an event from the request
            let srch = match SearchEvent::from_target_uuid_request(
                ident,
                target_uuid,
                &idms_prox_read.qs_read,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to begin radius read: {:?}", e);
                    return Err(e);
                }
            };

            trace!(?srch, "Begin event");

            // We have to use search_ext to guarantee acs was applied.
            match idms_prox_read.qs_read.search_ext(&srch) {
                Ok(mut entries) => {
                    let r = entries
                        .pop()
                        // From the entry, turn it into the value
                        .and_then(|entry| {
                            entry
                                .get_ava_single("radius_secret")
                                .and_then(|v| v.get_secret_str().map(str::to_string))
                        });
                    Ok(r)
                }
                Err(e) => Err(e),
            }
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "internalradiustokenread",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalradiustokenread(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<RadiusAuthToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;

        let res = spanned!("actors::v1_read::handle<InternalRadiusTokenReadMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;

            let target_uuid = idms_prox_read
                .qs_read
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!("Error resolving id to target");
                    e
                })?;

            // Make an event from the request
            let rate = match RadiusAuthTokenEvent::from_parts(
                // &idms_prox_read.qs_read,
                ident,
                target_uuid,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to begin radius token read: {:?}", e);
                    return Err(e);
                }
            };

            trace!(?rate, "Begin event");

            idms_prox_read.get_radiusauthtoken(&rate, ct)
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "internalunixusertokenread",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalunixusertokenread(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<UnixUserToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;

        let res = spanned!(
            "actors::v1_read::handle<InternalUnixUserTokenReadMessage>",
            {
                let ident = idms_prox_read
                    .validate_and_parse_uat(uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                    .map_err(|e| {
                        admin_error!("Invalid identity: {:?}", e);
                        e
                    })?;

                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(uuid_or_name.as_str())
                    .map_err(|e| {
                        admin_info!(
                            err = ?e,
                            "Error resolving {} as gidnumber continuing ...",
                            uuid_or_name
                        );
                        e
                    })?;

                // Make an event from the request
                let rate = match UnixUserTokenEvent::from_parts(ident, target_uuid) {
                    Ok(s) => s,
                    Err(e) => {
                        admin_error!("Failed to begin unix token read: {:?}", e);
                        return Err(e);
                    }
                };

                trace!(?rate, "Begin event");

                idms_prox_read.get_unixusertoken(&rate, ct)
            }
        );
        res
    }

    #[instrument(
        level = "trace",
        name = "internalunixgrouptokenread",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalunixgrouptokenread(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<UnixGroupToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!(
            "actors::v1_read::handle<InternalUnixGroupTokenReadMessage>",
            {
                let ident = idms_prox_read
                    .validate_and_parse_uat(uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                    .map_err(|e| {
                        admin_error!("Invalid identity: {:?}", e);
                        e
                    })?;

                let target_uuid = idms_prox_read
                    .qs_read
                    .name_to_uuid(uuid_or_name.as_str())
                    .map_err(|e| {
                        admin_info!(err = ?e, "Error resolving as gidnumber continuing");
                        e
                    })?;

                // Make an event from the request
                let rate = match UnixGroupTokenEvent::from_parts(
                    // &idms_prox_read.qs_read,
                    ident,
                    target_uuid,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        admin_error!("Failed to begin unix group token read: {:?}", e);
                        return Err(e);
                    }
                };

                trace!(?rate, "Begin event");

                idms_prox_read.get_unixgrouptoken(&rate)
            }
        );
        res
    }

    #[instrument(
        level = "trace",
        name = "internalsshkeyread",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsshkeyread(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Vec<String>, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<InternalSshKeyReadMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;
            let target_uuid = idms_prox_read
                .qs_read
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!("Error resolving id to target");
                    e
                })?;

            // Make an event from the request
            let srch = match SearchEvent::from_target_uuid_request(
                ident,
                target_uuid,
                &idms_prox_read.qs_read,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to begin ssh key read: {:?}", e);
                    return Err(e);
                }
            };

            trace!(?srch, "Begin event");

            match idms_prox_read.qs_read.search_ext(&srch) {
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
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "internalsshkeytagread",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsshkeytagread(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        tag: String,
        eventid: Uuid,
    ) -> Result<Option<String>, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<InternalSshKeyTagReadMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;
            let target_uuid = idms_prox_read
                .qs_read
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_info!("Error resolving id to target");
                    e
                })?;

            // Make an event from the request
            let srch = match SearchEvent::from_target_uuid_request(
                ident,
                target_uuid,
                &idms_prox_read.qs_read,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to begin sshkey tag read: {:?}", e);
                    return Err(e);
                }
            };

            trace!(?srch, "Begin event");

            match idms_prox_read.qs_read.search_ext(&srch) {
                Ok(mut entries) => {
                    let r = entries
                        .pop()
                        // get the first entry
                        .map(|e| {
                            // From the entry, turn it into the value
                            e.get_ava_set("ssh_publickey").and_then(|vs| {
                                // Get the one tagged value
                                vs.get_ssh_tag(&tag).map(str::to_string)
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
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmaccountunixauth",
        skip(self, uat, uuid_or_name, cred, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixauth(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        cred: String,
        eventid: Uuid,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idm_auth = self.idms.auth_async().await;
        // let res = spanned!("actors::v1_read::handle<IdmAccountUnixAuthMessage>", {
        // resolve the id
        let ident = idm_auth
            .validate_and_parse_uat(uat.as_deref(), ct)
            .and_then(|uat| idm_auth.process_uat_to_identity(&uat, ct))
            .map_err(|e| {
                admin_error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idm_auth
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_info!(err = ?e, "Error resolving as gidnumber continuing");
                e
            })?;
        // Make an event from the request
        let uuae = match UnixUserAuthEvent::from_parts(ident, target_uuid, cred) {
            Ok(s) => s,
            Err(e) => {
                admin_error!(err = ?e, "Failed to begin unix auth");
                return Err(e);
            }
        };

        security_info!(event = ?uuae, "Begin unix auth event");

        let res = idm_auth
            .auth_unix(&uuae, ct)
            .await
            .and_then(|r| idm_auth.commit().map(|_| r));

        security_info!(?res, "Sending result");

        // res });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmcredentialstatus",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialstatus(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<CredentialStatus, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;

        let res = spanned!("actors::v1_read::handle<IdmCredentialStatusMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;
            let target_uuid = idms_prox_read
                .qs_read
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving id to target");
                    e
                })?;

            // Make an event from the request
            let cse = match CredentialStatusEvent::from_parts(
                // &idms_prox_read.qs_read,
                ident,
                target_uuid,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin credential status read");
                    return Err(e);
                }
            };

            trace!(?cse, "Begin event");

            idms_prox_read.get_credentialstatus(&cse)
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmbackupcodeview",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmbackupcodeview(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<BackupCodesView, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read_async().await;

        let res = spanned!("actors::v1_read::handle<IdmBackupCodeViewMessage>", {
            let ident = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_read.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;
            let target_uuid = idms_prox_read
                .qs_read
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!("Error resolving id to target");
                    e
                })?;

            // Make an event from the request
            let rbce = match ReadBackupCodeEvent::from_parts(
                // &idms_prox_read.qs_read,
                ident,
                target_uuid,
            ) {
                Ok(s) => s,
                Err(e) => {
                    admin_error!("Failed to begin backup code read: {:?}", e);
                    return Err(e);
                }
            };

            trace!(?rbce, "Begin event");

            idms_prox_read.get_backup_codes(&rbce)
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "oauth2_authorise",
        skip(self, uat, auth_req, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise(
        &self,
        uat: Option<String>,
        auth_req: AuthorisationRequest,
        eventid: Uuid,
    ) -> Result<ConsentRequest, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<Oauth2Authorise>", {
            let (ident, uat) = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| {
                    idms_prox_read
                        .process_uat_to_identity(&uat, ct)
                        .map(|ident| (ident, uat))
                })
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    Oauth2Error::AuthenticationRequired
                })?;

            // Now we can send to the idm server for authorisation checking.
            idms_prox_read.check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "oauth2_authorise_permit",
        skip(self, uat, consent_req, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise_permit(
        &self,
        uat: Option<String>,
        consent_req: String,
        eventid: Uuid,
    ) -> Result<AuthorisePermitSuccess, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<Oauth2AuthorisePermit>", {
            let (ident, uat) = idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| {
                    idms_prox_read
                        .process_uat_to_identity(&uat, ct)
                        .map(|ident| (ident, uat))
                })
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;

            idms_prox_read.check_oauth2_authorise_permit(&ident, &uat, &consent_req, ct)
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "oauth2_authorise_permit",
        skip(self, client_authz, token_req, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_exchange(
        &self,
        client_authz: String,
        token_req: AccessTokenRequest,
        eventid: Uuid,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<Oauth2TokenExchange>", {
            // Now we can send to the idm server for authorisation checking.
            idms_prox_read.check_oauth2_token_exchange(&client_authz, &token_req, ct)
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "oauth2_token_introspect",
        skip(self, client_authz, intr_req, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_introspect(
        &self,
        client_authz: String,
        intr_req: AccessTokenIntrospectRequest,
        eventid: Uuid,
    ) -> Result<AccessTokenIntrospectResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let res = spanned!("actors::v1_read::handle<Oauth2TokenIntrospect>", {
            // Now we can send to the idm server for introspection checking.
            idms_prox_read.check_oauth2_token_introspect(&client_authz, &intr_req, ct)
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "auth_valid",
        skip(self, uat, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_auth_valid(
        &self,
        uat: Option<String>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;

        let res = spanned!("actors::v1_read::handle<AuthValid>", {
            idms_prox_read
                .validate_and_parse_uat(uat.as_deref(), ct)
                .map(|_| ())
                .map_err(|e| {
                    admin_error!("Invalid token: {:?}", e);
                    e
                })
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "ldaprequest",
        skip(self, eventid,  protomsg, uat)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_ldaprequest(
        &self,
        eventid: Uuid,
        protomsg: LdapMsg,
        uat: Option<LdapBoundToken>,
    ) -> Option<LdapResponseState> {
        // let res = spanned!( "actors::v1_read::handle<LdapRequestMessage>", {
        let res = match ServerOps::try_from(protomsg) {
            Ok(server_op) => self
                .ldap
                .do_op(&self.idms, server_op, uat, &eventid)
                .await
                .unwrap_or_else(|e| {
                    admin_error!("do_op failed -> {:?}", e);
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
        // });
        Some(res)
    }
}
