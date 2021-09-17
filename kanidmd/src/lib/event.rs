//! An `event` is a self contained module of data, that contains all of the
//! required information for any operation to proceed. While there are many
//! types of potential events, they all eventually lower to one of:
//!
//! * AuthEvent
//! * SearchEvent
//! * ExistsEvent
//! * ModifyEvent
//! * CreateEvent
//! * DeleteEvent
//!
//! An "event" is generally then passed to the `QueryServer` for processing.
//! By making these fully self contained units, it means that we can assert
//! at event creation time we have all the correct data requried to proceed
//! with the operation, and a clear path to know how to transform events between
//! various types.

use crate::entry::{Entry, EntryCommitted, EntryInit, EntryNew, EntryReduced};
use crate::filter::{Filter, FilterInvalid, FilterValid};
use crate::identity::Limits;
use crate::idm::AuthState;
use crate::modify::{ModifyInvalid, ModifyList, ModifyValid};
use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::value::PartialValue;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::ModifyList as ProtoModifyList;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{
    AuthCredential, AuthMech, AuthRequest, AuthStep, CreateRequest, DeleteRequest, ModifyRequest,
    SearchRequest, SearchResponse, UserAuthToken, WhoamiResponse,
};

use ldap3_server::simple::LdapFilter;
use std::collections::BTreeSet;
use std::time::Duration;
use uuid::Uuid;

#[cfg(test)]
use std::sync::Arc;

#[derive(Debug)]
pub struct SearchResult {
    entries: Vec<ProtoEntry>,
}

impl SearchResult {
    // ! TRACING INTEGRATED
    pub fn new(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        entries: &[Entry<EntryReduced, EntryCommitted>],
    ) -> Result<Self, OperationError> {
        let entries: Result<_, _> = entries
            .iter()
            .map(|e| {
                // All the needed transforms for this result are done
                // in search_ext. This is just an entry -> protoentry
                // step.
                e.to_pe(audit, qs)
            })
            .collect();
        Ok(SearchResult { entries: entries? })
    }

    // Consume self into a search response
    pub fn response(self) -> SearchResponse {
        SearchResponse {
            entries: self.entries,
        }
    }

    // Consume into the array of entries, used in the json proto
    pub fn into_proto_array(self) -> Vec<ProtoEntry> {
        self.entries
    }
}

#[derive(Debug)]
pub struct SearchEvent {
    pub ident: Identity,
    // This is the filter as we apply and process it.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
    pub attrs: Option<BTreeSet<AttrString>>,
}

impl SearchEvent {
    // ! TRACING INTEGRATED
    pub fn from_message(
        audit: &mut AuditScope,
        ident: Identity,
        req: &SearchRequest,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let f = Filter::from_ro(audit, &ident, &req.filter, qs)?;
        // We do need to do this twice to account for the ignore_hidden
        // changes.
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            // We can't get this from the SearchMessage because it's annoying with the
            // current macro design.
            attrs: None,
        })
    }

    pub fn from_internal_message(
        audit: &mut AuditScope,
        ident: Identity,
        filter: &Filter<FilterInvalid>,
        attrs: Option<&[String]>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let r_attrs: Option<BTreeSet<AttrString>> = attrs.map(|vs| {
            vs.iter()
                .filter_map(|a| qs.get_schema().normalise_attr_if_exists(a.as_str()))
                .collect()
        });

        if let Some(s) = &r_attrs {
            if s.is_empty() {
                request_error!("EmptyRequest for attributes");
                return Err(OperationError::EmptyRequest);
            }
        }

        let filter_orig = filter.validate(qs.get_schema()).map_err(|e| {
            request_error!(?e, "filter schema violation");
            OperationError::SchemaViolation(e)
        })?;
        let filter = filter_orig.clone().into_ignore_hidden();

        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: r_attrs,
        })
    }

    pub fn from_internal_recycle_message(
        _audit: &mut AuditScope,
        ident: Identity,
        filter: &Filter<FilterInvalid>,
        attrs: Option<&[String]>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let r_attrs: Option<BTreeSet<AttrString>> = attrs.map(|vs| {
            vs.iter()
                .filter_map(|a| qs.get_schema().normalise_attr_if_exists(a.as_str()))
                .collect()
        });

        if let Some(s) = &r_attrs {
            if s.is_empty() {
                return Err(OperationError::EmptyRequest);
            }
        }

        let filter_orig = filter
            .validate(qs.get_schema())
            .map(|f| f.into_recycled())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone();

        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: r_attrs,
        })
    }

    pub fn from_whoami_request(
        _audit: &mut AuditScope,
        ident: Identity,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = filter_all!(f_self())
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();

        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: None,
        })
    }

    pub fn from_target_uuid_request(
        _audit: &mut AuditScope,
        ident: Identity,
        target_uuid: Uuid,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)))
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: None,
        })
    }

    // Just impersonate the account with no filter changes.
    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            ident: Identity::from_impersonate_entry_ser(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            ident: Identity::from_impersonate_entry(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    pub fn new_impersonate(
        ident: &Identity,
        filter: Filter<FilterValid>,
        filter_orig: Filter<FilterValid>,
    ) -> Self {
        SearchEvent {
            ident: Identity::from_impersonate(ident),
            filter,
            filter_orig,
            attrs: None,
        }
    }

    #[cfg(test)]
    /* Impersonate a request for recycled objects */
    pub unsafe fn new_rec_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        let filter_orig = filter.into_valid();
        let filter = filter_orig.clone().into_recycled();
        SearchEvent {
            ident: Identity::from_impersonate_entry(e),
            filter,
            filter_orig,
            attrs: None,
        }
    }

    #[cfg(test)]
    /* Impersonate an external request AKA filter ts + recycle */
    pub unsafe fn new_ext_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            ident: Identity::from_impersonate_entry(e),
            filter: filter.clone().into_valid().into_ignore_hidden(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    pub(crate) fn new_ext_impersonate_uuid(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        ident: Identity,
        lf: &LdapFilter,
        attrs: Option<BTreeSet<AttrString>>,
    ) -> Result<Self, OperationError> {
        // Kanidm Filter from LdapFilter
        let f = Filter::from_ldap_ro(audit, &ident, lf, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs,
        })
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        SearchEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
            attrs: None,
        }
    }

    pub(crate) fn get_limits(&self) -> &Limits {
        &self.ident.limits
    }
}

// Represents the decoded entries from the protocol -> internal entry representation
// including information about the identity performing the request, and if the
// request is internal or not.
#[derive(Debug)]
pub struct CreateEvent {
    pub ident: Identity,
    // This may still actually change to handle the *raw* nature of the
    // input that we plan to parse.
    pub entries: Vec<Entry<EntryInit, EntryNew>>,
    // Is the CreateEvent from an internal or external source?
    // This may affect which plugins are run ...
}

impl CreateEvent {
    pub fn from_message(
        audit: &mut AuditScope,
        ident: Identity,
        req: &CreateRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let rentries: Result<Vec<_>, _> = req
            .entries
            .iter()
            .map(|e| Entry::from_proto_entry(audit, e, qs))
            .collect();
        // From ProtoEntry -> Entry
        // What is the correct consuming iterator here? Can we
        // even do that?
        match rentries {
            Ok(entries) => Ok(CreateEvent { ident, entries }),
            Err(e) => Err(e),
        }
    }

    // Is this an internal only function?
    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(
        e: &str,
        entries: Vec<Entry<EntryInit, EntryNew>>,
    ) -> Self {
        CreateEvent {
            ident: Identity::from_impersonate_entry_ser(e),
            entries,
        }
    }

    pub fn new_internal(entries: Vec<Entry<EntryInit, EntryNew>>) -> Self {
        CreateEvent {
            ident: Identity::from_internal(),
            entries,
        }
    }
}

#[derive(Debug)]
pub struct ExistsEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
}

impl ExistsEvent {
    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        ExistsEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        ExistsEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    pub(crate) fn get_limits(&self) -> &Limits {
        &self.ident.limits
    }
}

#[derive(Debug)]
pub struct DeleteEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
}

impl DeleteEvent {
    pub fn from_message(
        audit: &mut AuditScope,
        ident: Identity,
        req: &DeleteRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f = Filter::from_rw(audit, &ident, &req.filter, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(DeleteEvent {
            ident,
            filter,
            filter_orig,
        })
    }

    pub fn from_parts(
        _audit: &mut AuditScope,
        ident: Identity,
        f: &Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(DeleteEvent {
            ident,
            filter,
            filter_orig,
        })
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        DeleteEvent {
            ident: Identity::from_impersonate_entry(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            ident: Identity::from_impersonate_entry_ser(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        DeleteEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
        }
    }
}

#[derive(Debug)]
pub struct ModifyEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
    pub modlist: ModifyList<ModifyValid>,
}

impl ModifyEvent {
    pub fn from_message(
        audit: &mut AuditScope,
        ident: Identity,
        req: &ModifyRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f = Filter::from_rw(audit, &ident, &req.filter, qs)?;
        let m = ModifyList::from(audit, &req.modlist, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = m
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn from_parts(
        audit: &mut AuditScope,
        ident: Identity,
        target_uuid: Uuid,
        proto_ml: &ProtoModifyList,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f_uuid = filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let f = Filter::join_parts_and(f_uuid, filter);

        let m = ModifyList::from(audit, proto_ml, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = m
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn from_internal_parts(
        _audit: &mut AuditScope,
        ident: Identity,
        ml: &ModifyList<ModifyInvalid>,
        filter: &Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = filter
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = ml
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn from_target_uuid_attr_purge(
        _audit: &mut AuditScope,
        ident: Identity,
        target_uuid: Uuid,
        attr: &str,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let ml = ModifyList::new_purge(attr);
        let f_uuid = filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let f = Filter::join_parts_and(f_uuid, filter);

        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = ml
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn new_internal(filter: Filter<FilterValid>, modlist: ModifyList<ModifyValid>) -> Self {
        ModifyEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
            modlist,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(
        e: &str,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            ident: Identity::from_impersonate_entry_ser(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            ident: Identity::from_impersonate_entry(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
        }
    }

    pub fn new_impersonate(
        ident: &Identity,
        filter: Filter<FilterValid>,
        filter_orig: Filter<FilterValid>,
        modlist: ModifyList<ModifyValid>,
    ) -> Self {
        ModifyEvent {
            ident: Identity::from_impersonate(ident),
            filter,
            filter_orig,
            modlist,
        }
    }
}

#[derive(Debug)]
pub struct AuthEventStepInit {
    pub name: String,
    pub appid: Option<String>,
}

#[derive(Debug)]
pub struct AuthEventStepCred {
    pub sessionid: Uuid,
    pub cred: AuthCredential,
}

#[derive(Debug)]
pub struct AuthEventStepMech {
    pub sessionid: Uuid,
    pub mech: AuthMech,
}

#[derive(Debug)]
pub enum AuthEventStep {
    Init(AuthEventStepInit),
    Begin(AuthEventStepMech),
    Cred(AuthEventStepCred),
}

impl AuthEventStep {
    fn from_authstep(aus: AuthStep, sid: Option<Uuid>) -> Result<Self, OperationError> {
        match aus {
            AuthStep::Init(name) => {
                Ok(AuthEventStep::Init(AuthEventStepInit { name, appid: None }))
            }
            AuthStep::Begin(mech) => match sid {
                Some(ssid) => Ok(AuthEventStep::Begin(AuthEventStepMech {
                    sessionid: ssid,
                    mech,
                })),
                None => Err(OperationError::InvalidAuthState(
                    "session id not present in cred".to_string(),
                )),
            },
            AuthStep::Cred(cred) => match sid {
                Some(ssid) => Ok(AuthEventStep::Cred(AuthEventStepCred {
                    sessionid: ssid,
                    cred,
                })),
                None => Err(OperationError::InvalidAuthState(
                    "session id not present in cred".to_string(),
                )),
            },
        }
    }

    #[cfg(test)]
    pub fn anonymous_init() -> Self {
        AuthEventStep::Init(AuthEventStepInit {
            name: "anonymous".to_string(),
            appid: None,
        })
    }

    #[cfg(test)]
    pub fn named_init(name: &str) -> Self {
        AuthEventStep::Init(AuthEventStepInit {
            name: name.to_string(),
            appid: None,
        })
    }

    #[cfg(test)]
    pub fn begin_mech(sessionid: Uuid, mech: AuthMech) -> Self {
        AuthEventStep::Begin(AuthEventStepMech { sessionid, mech })
    }

    #[cfg(test)]
    pub fn cred_step_anonymous(sid: Uuid) -> Self {
        AuthEventStep::Cred(AuthEventStepCred {
            sessionid: sid,
            cred: AuthCredential::Anonymous,
        })
    }

    #[cfg(test)]
    pub fn cred_step_password(sid: Uuid, pw: &str) -> Self {
        AuthEventStep::Cred(AuthEventStepCred {
            sessionid: sid,
            cred: AuthCredential::Password(pw.to_string()),
        })
    }
}

#[derive(Debug)]
pub struct AuthEvent {
    pub ident: Option<Identity>,
    pub step: AuthEventStep,
    // pub sessionid: Option<Uuid>,
}

impl AuthEvent {
    pub fn from_message(sessionid: Option<Uuid>, req: AuthRequest) -> Result<Self, OperationError> {
        Ok(AuthEvent {
            ident: None,
            step: AuthEventStep::from_authstep(req.step, sessionid)?,
        })
    }

    #[cfg(test)]
    pub fn anonymous_init() -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::anonymous_init(),
        }
    }

    #[cfg(test)]
    pub fn named_init(name: &str) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::named_init(name),
        }
    }

    #[cfg(test)]
    pub fn begin_mech(sessionid: Uuid, mech: AuthMech) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::begin_mech(sessionid, mech),
        }
    }

    #[cfg(test)]
    pub fn cred_step_anonymous(sid: Uuid) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::cred_step_anonymous(sid),
        }
    }

    #[cfg(test)]
    pub fn cred_step_password(sid: Uuid, pw: &str) -> Self {
        AuthEvent {
            ident: None,
            step: AuthEventStep::cred_step_password(sid, pw),
        }
    }
}

// Probably should be a struct with the session id present.
#[derive(Debug)]
pub struct AuthResult {
    pub sessionid: Uuid,
    pub state: AuthState,
    pub delay: Option<Duration>,
}

/*
impl AuthResult {
    pub fn response(self) -> AuthResponse {
        AuthResponse {
            sessionid: self.sessionid,
            state: self.state,
        }
    }
}
*/

pub struct WhoamiResult {
    youare: ProtoEntry,
    uat: UserAuthToken,
}

impl WhoamiResult {
    pub fn new(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        e: &Entry<EntryReduced, EntryCommitted>,
        uat: UserAuthToken,
    ) -> Result<Self, OperationError> {
        Ok(WhoamiResult {
            youare: e.to_pe(audit, qs)?,
            uat,
        })
    }

    pub fn response(self) -> WhoamiResponse {
        WhoamiResponse {
            youare: self.youare,
            uat: self.uat,
        }
    }
}

#[derive(Debug)]
pub struct PurgeTombstoneEvent {
    pub ident: Identity,
    pub eventid: Uuid,
}

impl Default for PurgeTombstoneEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl PurgeTombstoneEvent {
    pub fn new() -> Self {
        PurgeTombstoneEvent {
            ident: Identity::from_internal(),
            eventid: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
pub struct PurgeRecycledEvent {
    pub ident: Identity,
    pub eventid: Uuid,
}

impl Default for PurgeRecycledEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl PurgeRecycledEvent {
    pub fn new() -> Self {
        PurgeRecycledEvent {
            ident: Identity::from_internal(),
            eventid: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
pub struct OnlineBackupEvent {
    pub ident: Identity,
    pub eventid: Uuid,
}

impl Default for OnlineBackupEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl OnlineBackupEvent {
    pub fn new() -> Self {
        OnlineBackupEvent {
            ident: Identity::from_internal(),
            eventid: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
pub struct ReviveRecycledEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // Unlike the others, because of how this works, we don't need the orig filter
    // to be retained, because the filter is the orig filter for this check.
    //
    // It will be duplicated into the modify ident as it exists.
}

impl ReviveRecycledEvent {
    pub fn from_parts(
        _audit: &mut AuditScope,
        ident: Identity,
        filter: &Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let filter = filter
            .validate(qs.get_schema())
            .map(|f| f.into_recycled())
            .map_err(OperationError::SchemaViolation)?;
        Ok(ReviveRecycledEvent { ident, filter })
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        ReviveRecycledEvent {
            ident: Identity::from_impersonate_entry(e),
            filter: filter.into_valid(),
        }
    }
}
