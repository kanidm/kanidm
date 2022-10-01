use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kanidm_proto::v1::{
    ApiToken, AuthRequest, BackupCodesView, CURequest, CUSessionToken, CUStatus, CredentialStatus,
    Entry as ProtoEntry, OperationError, RadiusAuthToken, SearchRequest, SearchResponse,
    UnixGroupToken, UnixUserToken, WhoamiResponse,
};
use ldap3_proto::simple::*;
use regex::Regex;
use tracing::{error, info, instrument, trace};
use uuid::Uuid;

use crate::be::BackendTransaction;
use crate::event::{
    AuthEvent, AuthResult, OnlineBackupEvent, SearchEvent, SearchResult, WhoamiResult,
};
use crate::filter::{Filter, FilterInvalid};
use crate::idm::credupdatesession::CredentialUpdateSessionToken;
use crate::idm::event::{
    CredentialStatusEvent, RadiusAuthTokenEvent, ReadBackupCodeEvent, UnixGroupTokenEvent,
    UnixUserAuthEvent, UnixUserTokenEvent,
};
use crate::idm::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AuthorisationRequest, AuthorisePermitSuccess, AuthoriseResponse,
    JwkKeySet, Oauth2Error, OidcDiscoveryResponse, OidcToken,
};
use crate::idm::server::{IdmServer, IdmServerTransaction};
use crate::idm::serviceaccount::ListApiTokenEvent;
use crate::ldap::{LdapBoundToken, LdapResponseState, LdapServer};
use crate::prelude::*;

// ===========================================================

pub struct QueryServerReadV1 {
    idms: Arc<IdmServer>,
    ldap: Arc<LdapServer>,
}

impl QueryServerReadV1 {
    pub fn new(idms: Arc<IdmServer>, ldap: Arc<LdapServer>) -> Self {
        info!("Starting query server v1 worker ...");
        QueryServerReadV1 {
            idms,
            ldap,
        }
    }

    pub fn start_static(
        idms: Arc<IdmServer>,
        ldap: Arc<LdapServer>,
    ) -> &'static Self {
        let x = Box::new(QueryServerReadV1::new(idms, ldap));

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
        level = "info",
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
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
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
        level = "info",
        name = "online_backup",
        skip_all,
        fields(uuid = ?msg.eventid)
    )]
    pub async fn handle_online_backup(
        &self,
        msg: OnlineBackupEvent,
        outpath: &str,
        versions: usize,
    ) -> Result<(), OperationError> {
        trace!(eventid = ?msg.eventid, "Begin online backup event");

        #[allow(deprecated)]
        let now = time::OffsetDateTime::now_local();
        let timestamp = now.format(time::Format::Rfc3339);
        let dest_file = format!("{}/backup-{}.json", outpath, timestamp);

        if Path::new(&dest_file).exists() {
            error!(
                "Online backup file {} already exists, will not overwrite it.",
                dest_file
            );
            return Err(OperationError::InvalidState);
        }

        // Scope to limit the read txn.
        {
            let idms_prox_read = self.idms.proxy_read_async().await;
            idms_prox_read
                .qs_read
                .get_be_txn()
                .backup(&dest_file)
                .map(|()| {
                    info!("Online backup created {} successfully", dest_file);
                })
                .map_err(|e| {
                    error!("Online backup failed to create {}: {:?}", dest_file, e);
                    OperationError::InvalidState
                })?;
        }

        // pattern to find automatically generated backup files
        let re = Regex::new(r"^backup-\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\.json$").map_err(
            |error| {
                error!(
                    "Failed to parse regexp for online backup files: {:?}",
                    error
                );
                OperationError::InvalidState
            },
        )?;

        // cleanup of maximum backup versions to keep
        let mut backup_file_list: Vec<PathBuf> = Vec::new();
        // get a list of backup files
        match fs::read_dir(outpath) {
            Ok(rd) => {
                for entry in rd {
                    // get PathBuf
                    let pb = entry
                        .map_err(|e| {
                            error!(?e, "Pathbuf access");
                            OperationError::InvalidState
                        })?
                        .path();

                    // skip everything that is not a file
                    if !pb.is_file() {
                        continue;
                    }

                    // get the /some/dir/<file_name> of the file
                    let file_name = pb.file_name().and_then(|f| f.to_str()).ok_or_else(|| {
                        error!("filename is invalid");
                        OperationError::InvalidState
                    })?;
                    // check for a online backup file
                    if re.is_match(file_name) {
                        backup_file_list.push(pb.clone());
                    }
                }
            }
            Err(e) => {
                error!("Online backup cleanup error read dir {}: {}", outpath, e);
                return Err(OperationError::InvalidState);
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

        Ok(())
    }

    #[instrument(
        level = "info",
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
        // Make an event from the whoami request. This will process the event and
        // generate a selfuuid search.
        //
        // This current handles the unauthenticated check, and will
        // trigger the failure, but if we can manage to work out async
        // then move this to core.rs, and don't allow Option<UAT> to get
        // this far.
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
                WhoamiResult::new(&idms_prox_read.qs_read, &e).map(WhoamiResult::response)
            }
            Some(_) => Err(OperationError::InvalidState), /* Somehow matched multiple entries... */
            _ => Err(OperationError::NoMatchingEntries),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
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
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
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

        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
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
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
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

        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
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

        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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

    #[instrument(
        level = "info",
        skip_all,
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
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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

    #[instrument(
        level = "info",
        skip_all,
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
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
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
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_api_token_get(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Vec<ApiToken>, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
            .map_err(|e| {
                admin_error!("Invalid identity: {:?}", e);
                e
            })?;
        let target = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_error!("Error resolving id to target");
                e
            })?;

        let lte = ListApiTokenEvent { ident, target };

        idms_prox_read.service_account_list_api_token(&lte)
    }

    #[instrument(
        level = "info",
        skip_all,
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
        // resolve the id
        let ident = idm_auth
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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

        res
    }

    #[instrument(
        level = "info",
        skip_all,
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

        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
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

        let ident = idms_prox_read
            .validate_and_parse_token_to_ident(uat.as_deref(), ct)
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
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdatestatus(
        &self,
        session_token: CUSessionToken,
        eventid: Uuid,
    ) -> Result<CUStatus, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_cred_update = self.idms.cred_update_transaction_async().await;
        let session_token = CredentialUpdateSessionToken {
            token_enc: session_token.token,
        };

        idms_cred_update
            .credential_update_status(&session_token, ct)
            .map_err(|e| {
                admin_error!(
                    err = ?e,
                    "Failed to begin credential_update_status",
                );
                e
            })
            .map(|sta| sta.into())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdate(
        &self,
        session_token: CUSessionToken,
        scr: CURequest,
        eventid: Uuid,
    ) -> Result<CUStatus, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_cred_update = self.idms.cred_update_transaction_async().await;
        let session_token = CredentialUpdateSessionToken {
            token_enc: session_token.token,
        };

        debug!(?scr);

        match scr {
            CURequest::PrimaryRemove => idms_cred_update
                .credential_primary_delete(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_delete",
                    );
                    e
                }),
            CURequest::Password(pw) => idms_cred_update
                .credential_primary_set_password(&session_token, ct, &pw)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_set_password",
                    );
                    e
                }),
            CURequest::CancelMFAReg => idms_cred_update
                .credential_update_cancel_mfareg(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_update_cancel_mfareg",
                    );
                    e
                }),
            CURequest::TotpGenerate => idms_cred_update
                .credential_primary_init_totp(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_init_totp",
                    );
                    e
                }),
            CURequest::TotpVerify(totp_chal) => idms_cred_update
                .credential_primary_check_totp(&session_token, ct, totp_chal)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_check_totp",
                    );
                    e
                }),
            CURequest::TotpAcceptSha1 => idms_cred_update
                .credential_primary_accept_sha1_totp(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_accept_sha1_totp",
                    );
                    e
                }),
            CURequest::TotpRemove => idms_cred_update
                .credential_primary_remove_totp(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_remove_totp",
                    );
                    e
                }),
            CURequest::BackupCodeGenerate => idms_cred_update
                .credential_primary_init_backup_codes(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_init_backup_codes",
                    );
                    e
                }),
            CURequest::BackupCodeRemove => idms_cred_update
                .credential_primary_remove_backup_codes(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_primary_remove_backup_codes",
                    );
                    e
                }),
            CURequest::PasskeyInit => idms_cred_update
                .credential_passkey_init(&session_token, ct)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_passkey_init",
                    );
                    e
                }),
            CURequest::PasskeyFinish(label, rpkc) => idms_cred_update
                .credential_passkey_finish(&session_token, ct, label, &rpkc)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_passkey_init",
                    );
                    e
                }),
            CURequest::PasskeyRemove(uuid) => idms_cred_update
                .credential_passkey_remove(&session_token, ct, uuid)
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin credential_passkey_init",
                    );
                    e
                }),
        }
        .map(|sta| sta.into())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise(
        &self,
        uat: Option<String>,
        auth_req: AuthorisationRequest,
        eventid: Uuid,
    ) -> Result<AuthoriseResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
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
    }

    #[instrument(
        level = "info",
        skip_all,
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
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise_reject(
        &self,
        uat: Option<String>,
        consent_req: String,
        eventid: Uuid,
    ) -> Result<Url, OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
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

        idms_prox_read.check_oauth2_authorise_reject(&ident, &uat, &consent_req, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_exchange(
        &self,
        client_authz: Option<String>,
        token_req: AccessTokenRequest,
        eventid: Uuid,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        // Now we can send to the idm server for authorisation checking.
        idms_prox_read.check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
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
        // Now we can send to the idm server for introspection checking.
        idms_prox_read.check_oauth2_token_introspect(&client_authz, &intr_req, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_openid_userinfo(
        &self,
        client_id: String,
        client_authz: String,
        eventid: Uuid,
    ) -> Result<OidcToken, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;
        idms_prox_read.oauth2_openid_userinfo(&client_id, &client_authz, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_openid_discovery(
        &self,
        client_id: String,
        eventid: Uuid,
    ) -> Result<OidcDiscoveryResponse, OperationError> {
        let idms_prox_read = self.idms.proxy_read_async().await;
        idms_prox_read.oauth2_openid_discovery(&client_id)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_openid_publickey(
        &self,
        client_id: String,
        eventid: Uuid,
    ) -> Result<JwkKeySet, OperationError> {
        let idms_prox_read = self.idms.proxy_read_async().await;
        idms_prox_read.oauth2_openid_publickey(&client_id)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn get_domain_display_name(&self, eventid: Uuid) -> String {
        let idms_prox_read = self.idms.proxy_read_async().await;
        idms_prox_read.qs_read.get_domain_display_name().to_string()
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_auth_valid(
        &self,
        uat: Option<String>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let idms_prox_read = self.idms.proxy_read_async().await;

        idms_prox_read
            .validate_and_parse_uat(uat.as_deref(), ct)
            .map(|_| ())
            .map_err(|e| {
                admin_error!("Invalid token: {:?}", e);
                e
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_ldaprequest(
        &self,
        eventid: Uuid,
        protomsg: LdapMsg,
        uat: Option<LdapBoundToken>,
    ) -> Option<LdapResponseState> {
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
        Some(res)
    }
}
