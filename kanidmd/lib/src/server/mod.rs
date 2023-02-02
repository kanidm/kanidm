//! `server` contains the query server, which is the main high level construction
//! to coordinate queries and operations in the server.

use std::str::FromStr;
use std::sync::Arc;

use crate::prelude::*;

use concread::arcache::{ARCache, ARCacheBuilder, ARCacheReadTxn};
use concread::cowcell::*;
use hashbrown::HashSet;
use kanidm_proto::v1::{ConsistencyError, UiHint};
use tokio::sync::{Semaphore, SemaphorePermit};
use tracing::trace;

use self::access::{
    profiles::{
        AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlSearch,
    },
    AccessControls, AccessControlsReadTransaction, AccessControlsTransaction,
    AccessControlsWriteTransaction,
};

use crate::be::{Backend, BackendReadTransaction, BackendTransaction, BackendWriteTransaction};
// We use so many, we just import them all ...
use crate::filter::{Filter, FilterInvalid, FilterValid, FilterValidResolved};
use crate::plugins::dyngroup::{DynGroup, DynGroupCache};
use crate::plugins::Plugins;
use crate::repl::cid::Cid;
use crate::schema::{
    Schema, SchemaAttribute, SchemaClass, SchemaReadTransaction, SchemaTransaction,
    SchemaWriteTransaction,
};
use crate::valueset::uuid_to_proto_string;

pub mod access;
pub mod batch_modify;
pub mod create;
pub mod delete;
pub mod identity;
pub mod migrations;
pub mod modify;
pub mod recycle;

const RESOLVE_FILTER_CACHE_MAX: usize = 4096;
const RESOLVE_FILTER_CACHE_LOCAL: usize = 0;

pub type ResolveFilterCacheReadTxn<'a> =
    ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>;

#[derive(Debug, Clone, PartialOrd, PartialEq, Eq)]
enum ServerPhase {
    Bootstrap,
    SchemaReady,
    Running,
}

#[derive(Debug, Clone)]
struct DomainInfo {
    d_uuid: Uuid,
    d_name: String,
    d_display: String,
}

#[derive(Clone)]
pub struct QueryServer {
    phase: Arc<CowCell<ServerPhase>>,
    s_uuid: Uuid,
    d_info: Arc<CowCell<DomainInfo>>,
    be: Backend,
    schema: Arc<Schema>,
    accesscontrols: Arc<AccessControls>,
    db_tickets: Arc<Semaphore>,
    write_ticket: Arc<Semaphore>,
    resolve_filter_cache:
        Arc<ARCache<(IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>>>,
    dyngroup_cache: Arc<CowCell<DynGroupCache>>,
}

pub struct QueryServerReadTransaction<'a> {
    be_txn: BackendReadTransaction<'a>,
    // Anything else? In the future, we'll need to have a schema transaction
    // type, maybe others?
    d_info: CowCellReadTxn<DomainInfo>,
    schema: SchemaReadTransaction,
    accesscontrols: AccessControlsReadTransaction<'a>,
    _db_ticket: SemaphorePermit<'a>,
    resolve_filter_cache:
        ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>,
}

unsafe impl<'a> Sync for QueryServerReadTransaction<'a> {}

unsafe impl<'a> Send for QueryServerReadTransaction<'a> {}

pub struct QueryServerWriteTransaction<'a> {
    committed: bool,
    phase: CowCellWriteTxn<'a, ServerPhase>,
    d_info: CowCellWriteTxn<'a, DomainInfo>,
    curtime: Duration,
    cid: Cid,
    be_txn: BackendWriteTransaction<'a>,
    schema: SchemaWriteTransaction<'a>,
    accesscontrols: AccessControlsWriteTransaction<'a>,
    // We store a set of flags that indicate we need a reload of
    // schema or acp, which is tested by checking the classes of the
    // changing content.
    changed_schema: bool,
    changed_acp: bool,
    changed_oauth2: bool,
    changed_domain: bool,
    // Store the list of changed uuids for other invalidation needs?
    changed_uuid: HashSet<Uuid>,
    _db_ticket: SemaphorePermit<'a>,
    _write_ticket: SemaphorePermit<'a>,
    resolve_filter_cache:
        ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>,
    dyngroup_cache: CowCellWriteTxn<'a, DynGroupCache>,
}

/// The `QueryServerTransaction` trait provides a set of common read only operations to be
/// shared between [`QueryServerReadTransaction`] and [`QueryServerWriteTransaction`]s.
///
/// These operations tend to be high level constructions, generally different types of searches
/// that are capable of taking different types of parameters and applying access controls or not,
/// impersonating accounts, or bypassing these via internal searches.
///
/// [`QueryServerReadTransaction`]: struct.QueryServerReadTransaction.html
/// [`QueryServerWriteTransaction`]: struct.QueryServerWriteTransaction.html
pub trait QueryServerTransaction<'a> {
    type BackendTransactionType: BackendTransaction;
    fn get_be_txn(&mut self) -> &mut Self::BackendTransactionType;

    type SchemaTransactionType: SchemaTransaction;
    fn get_schema<'b>(&self) -> &'b Self::SchemaTransactionType;

    type AccessControlsTransactionType: AccessControlsTransaction<'a>;
    fn get_accesscontrols(&self) -> &Self::AccessControlsTransactionType;

    fn get_domain_uuid(&self) -> Uuid;

    fn get_domain_name(&self) -> &str;

    fn get_domain_display_name(&self) -> &str;

    fn get_resolve_filter_cache(&mut self) -> &mut ResolveFilterCacheReadTxn<'a>;

    // Because of how borrowck in rust works, if we need to get two inner types we have to get them
    // in a single fn.

    fn get_resolve_filter_cache_and_be_txn(
        &mut self,
    ) -> (
        &mut Self::BackendTransactionType,
        &mut ResolveFilterCacheReadTxn<'a>,
    );

    /// Conduct a search and apply access controls to yield a set of entries that
    /// have been reduced to the set of user visible avas. Note that if you provide
    /// a `SearchEvent` for the internal user, this query will fail. It is invalid for
    /// the [`access`] module to attempt to reduce avas for internal searches, and you
    /// should use [`fn search`] instead.
    ///
    /// [`SearchEvent`]: ../event/struct.SearchEvent.html
    /// [`access`]: ../access/index.html
    /// [`fn search`]: trait.QueryServerTransaction.html#method.search
    #[instrument(level = "debug", skip_all)]
    fn search_ext(
        &mut self,
        se: &SearchEvent,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        /*
         * This just wraps search, but it's for the external interface
         * so as a result it also reduces the entry set's attributes at
         * the end.
         */
        let entries = self.search(se)?;

        let access = self.get_accesscontrols();
        access
            .search_filter_entry_attributes(se, entries)
            .map_err(|e| {
                // Log and fail if something went wrong.
                admin_error!(?e, "Failed to filter entry attributes");
                e
            })
        // This now returns the reduced vec.
    }

    #[instrument(level = "debug", skip_all)]
    fn search(
        &mut self,
        se: &SearchEvent,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        if se.ident.is_internal() {
            trace!(internal_filter = ?se.filter, "search");
        } else {
            security_info!(initiator = %se.ident, "search");
            admin_info!(external_filter = ?se.filter, "search");
        }

        // This is an important security step because it prevents us from
        // performing un-indexed searches on attr's that don't exist in the
        // server. This is why ExtensibleObject can only take schema that
        // exists in the server, not arbitrary attr names.
        //
        // This normalises and validates in a single step.
        //
        // NOTE: Filters are validated in event conversion.

        let (be_txn, resolve_filter_cache) = self.get_resolve_filter_cache_and_be_txn();
        let idxmeta = be_txn.get_idxmeta_ref();
        // Now resolve all references and indexes.
        let vfr = se
            .filter
            .resolve(&se.ident, Some(idxmeta), Some(resolve_filter_cache))
            .map_err(|e| {
                admin_error!(?e, "search filter resolve failure");
                e
            })?;

        let lims = se.get_limits();

        // NOTE: We currently can't build search plugins due to the inability to hand
        // the QS wr/ro to the plugin trait. However, there shouldn't be a need for search
        // plugins, because all data transforms should be in the write path.

        let res = self.get_be_txn().search(lims, &vfr).map_err(|e| {
            admin_error!(?e, "backend failure");
            OperationError::Backend
        })?;

        // Apply ACP before we let the plugins "have at it".
        // WARNING; for external searches this is NOT the only
        // ACP application. There is a second application to reduce the
        // attribute set on the entries!
        //
        let access = self.get_accesscontrols();
        access.search_filter_entries(se, res).map_err(|e| {
            admin_error!(?e, "Unable to access filter entries");
            e
        })
    }

    #[instrument(level = "debug", skip_all)]
    fn exists(&mut self, ee: &ExistsEvent) -> Result<bool, OperationError> {
        let (be_txn, resolve_filter_cache) = self.get_resolve_filter_cache_and_be_txn();
        let idxmeta = be_txn.get_idxmeta_ref();

        let vfr = ee
            .filter
            .resolve(&ee.ident, Some(idxmeta), Some(resolve_filter_cache))
            .map_err(|e| {
                admin_error!(?e, "Failed to resolve filter");
                e
            })?;

        let lims = ee.get_limits();

        be_txn.exists(lims, &vfr).map_err(|e| {
            admin_error!(?e, "backend failure");
            OperationError::Backend
        })
    }

    fn name_to_uuid(&mut self, name: &str) -> Result<Uuid, OperationError> {
        // Is it just a uuid?
        Uuid::parse_str(name).or_else(|_| {
            let lname = name.to_lowercase();
            self.get_be_txn()
                .name2uuid(lname.as_str())?
                .ok_or(OperationError::NoMatchingEntries)
        })
    }

    // Similar to name, but where we lookup from external_id instead.
    fn sync_external_id_to_uuid(
        &mut self,
        external_id: &str,
    ) -> Result<Option<Uuid>, OperationError> {
        // Is it just a uuid?
        Uuid::parse_str(external_id).map(Some).or_else(|_| {
            let lname = external_id.to_lowercase();
            self.get_be_txn().externalid2uuid(lname.as_str())
        })
    }

    fn uuid_to_spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError> {
        let r = self.get_be_txn().uuid2spn(uuid)?;

        if let Some(ref n) = r {
            // Shouldn't we be doing more graceful error handling here?
            // Or, if we know it will always be true, we should remove this.
            debug_assert!(n.is_spn() || n.is_iname());
        }

        Ok(r)
    }

    fn uuid_to_rdn(&mut self, uuid: Uuid) -> Result<String, OperationError> {
        // If we have a some, pass it on, else unwrap into a default.
        self.get_be_txn()
            .uuid2rdn(uuid)
            .map(|v| v.unwrap_or_else(|| format!("uuid={}", uuid.as_hyphenated())))
    }

    /// From internal, generate an "exists" event and dispatch
    #[instrument(level = "debug", skip_all)]
    fn internal_exists(&mut self, filter: Filter<FilterInvalid>) -> Result<bool, OperationError> {
        // Check the filter
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        // Build an exists event
        let ee = ExistsEvent::new_internal(f_valid);
        // Submit it
        self.exists(&ee)
    }

    #[instrument(level = "debug", skip_all)]
    fn internal_search(
        &mut self,
        filter: Filter<FilterInvalid>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let se = SearchEvent::new_internal(f_valid);
        self.search(&se)
    }

    #[instrument(level = "debug", skip_all)]
    fn impersonate_search_valid(
        &mut self,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        event: &Identity,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let se = SearchEvent::new_impersonate(event, f_valid, f_intent_valid);
        self.search(&se)
    }

    /// Applies ACP to filter result entries.
    fn impersonate_search_ext_valid(
        &mut self,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        event: &Identity,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        let se = SearchEvent::new_impersonate(event, f_valid, f_intent_valid);
        self.search_ext(&se)
    }

    // Who they are will go here
    fn impersonate_search(
        &mut self,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        event: &Identity,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        self.impersonate_search_valid(f_valid, f_intent_valid, event)
    }

    #[instrument(level = "debug", skip_all)]
    fn impersonate_search_ext(
        &mut self,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        event: &Identity,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        self.impersonate_search_ext_valid(f_valid, f_intent_valid, event)
    }

    /// Get a single entry by its UUID. This is used heavily for internal
    /// server operations, especially in login and ACP checks.
    #[instrument(level = "debug", skip_all)]
    fn internal_search_uuid(
        &mut self,
        uuid: Uuid,
    ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
        let filter = filter!(f_eq("uuid", PartialValue::Uuid(uuid)));
        let f_valid = filter.validate(self.get_schema()).map_err(|e| {
            error!(?e, "Filter Validate - SchemaViolation");
            OperationError::SchemaViolation(e)
        })?;
        let se = SearchEvent::new_internal(f_valid);

        let mut vs = self.search(&se)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => Ok(entry),
            _ => Err(OperationError::NoMatchingEntries),
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn impersonate_search_ext_uuid(
        &mut self,
        uuid: Uuid,
        event: &Identity,
    ) -> Result<Entry<EntryReduced, EntryCommitted>, OperationError> {
        let filter_intent = filter_all!(f_eq("uuid", PartialValue::Uuid(uuid)));
        let filter = filter!(f_eq("uuid", PartialValue::Uuid(uuid)));

        let mut vs = self.impersonate_search_ext(filter, filter_intent, event)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => Ok(entry),
            _ => Err(OperationError::NoMatchingEntries),
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn impersonate_search_uuid(
        &mut self,
        uuid: Uuid,
        event: &Identity,
    ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
        let filter_intent = filter_all!(f_eq("uuid", PartialValue::Uuid(uuid)));
        let filter = filter!(f_eq("uuid", PartialValue::Uuid(uuid)));

        let mut vs = self.impersonate_search(filter, filter_intent, event)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => Ok(entry),
            _ => Err(OperationError::NoMatchingEntries),
        }
    }

    /// Do a schema aware conversion from a String:String to String:Value for modification
    /// present.
    fn clone_value(&mut self, attr: &str, value: &str) -> Result<Value, OperationError> {
        let schema = self.get_schema();

        // Should this actually be a fn of Value - no - I think that introduces issues with the
        // monomorphisation of the trait for transactions, so we should have this here.

        // Lookup the attr
        match schema.get_attributes().get(attr) {
            Some(schema_a) => {
                match schema_a.syntax {
                    SyntaxType::Utf8String => Ok(Value::new_utf8(value.to_string())),
                    SyntaxType::Utf8StringInsensitive => Ok(Value::new_iutf8(value)),
                    SyntaxType::Utf8StringIname => Ok(Value::new_iname(value)),
                    SyntaxType::Boolean => Value::new_bools(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid boolean syntax".to_string())),
                    SyntaxType::SyntaxId => Value::new_syntaxs(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Syntax syntax".to_string())),
                    SyntaxType::IndexId => Value::new_indexes(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Index syntax".to_string())),
                    SyntaxType::Uuid => {
                        // Attempt to resolve this name to a uuid. If it's already a uuid, then
                        // name to uuid will "do the right thing" and give us the Uuid back.
                        let un = self
                            .name_to_uuid(value)
                            .unwrap_or(UUID_DOES_NOT_EXIST);
                        Ok(Value::Uuid(un))
                    }
                    SyntaxType::ReferenceUuid => {
                        let un = self
                            .name_to_uuid(value)
                            .unwrap_or(UUID_DOES_NOT_EXIST);
                        Ok(Value::Refer(un))
                    }
                    SyntaxType::JsonFilter => Value::new_json_filter_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Filter syntax".to_string())),
                    SyntaxType::Credential => Err(OperationError::InvalidAttribute("Credentials can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SecretUtf8String => Err(OperationError::InvalidAttribute("Radius secrets can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SshKey => Err(OperationError::InvalidAttribute("SSH public keys can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SecurityPrincipalName => Err(OperationError::InvalidAttribute("SPNs are generated and not able to be set.".to_string())),
                    SyntaxType::Uint32 => Value::new_uint32_str(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid uint32 syntax".to_string())),
                    SyntaxType::Cid => Err(OperationError::InvalidAttribute("CIDs are generated and not able to be set.".to_string())),
                    SyntaxType::NsUniqueId => Value::new_nsuniqueid_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid NsUniqueId syntax".to_string())),
                    SyntaxType::DateTime => Value::new_datetime_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid DateTime (rfc3339) syntax".to_string())),
                    SyntaxType::EmailAddress => Value::new_email_address_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Email Address syntax".to_string())),
                    SyntaxType::Url => Value::new_url_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Url (whatwg/url) syntax".to_string())),
                    SyntaxType::OauthScope => Value::new_oauthscope(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Oauth Scope syntax".to_string())),
                    SyntaxType::OauthScopeMap => Err(OperationError::InvalidAttribute("Oauth Scope Maps can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::PrivateBinary => Err(OperationError::InvalidAttribute("Private Binary Values can not be supplied through modification".to_string())),
                    SyntaxType::IntentToken => Err(OperationError::InvalidAttribute("Intent Token Values can not be supplied through modification".to_string())),
                    SyntaxType::Passkey => Err(OperationError::InvalidAttribute("Passkey Values can not be supplied through modification".to_string())),
                    SyntaxType::DeviceKey => Err(OperationError::InvalidAttribute("DeviceKey Values can not be supplied through modification".to_string())),
                    SyntaxType::Session => Err(OperationError::InvalidAttribute("Session Values can not be supplied through modification".to_string())),
                    SyntaxType::JwsKeyEs256 => Err(OperationError::InvalidAttribute("JwsKeyEs256 Values can not be supplied through modification".to_string())),
                    SyntaxType::JwsKeyRs256 => Err(OperationError::InvalidAttribute("JwsKeyRs256 Values can not be supplied through modification".to_string())),
                    SyntaxType::Oauth2Session => Err(OperationError::InvalidAttribute("Oauth2Session Values can not be supplied through modification".to_string())),
                    SyntaxType::UiHint => UiHint::from_str(value)
                        .map(Value::UiHint)
                        .map_err(|()| OperationError::InvalidAttribute("Invalid uihint syntax".to_string())),
                    SyntaxType::TotpSecret => Err(OperationError::InvalidAttribute("TotpSecret Values can not be supplied through modification".to_string())),
                }
            }
            None => {
                // No attribute of this name exists - fail fast, there is no point to
                // proceed, as nothing can be satisfied.
                Err(OperationError::InvalidAttributeName(attr.to_string()))
            }
        }
    }

    fn clone_partialvalue(
        &mut self,
        attr: &str,
        value: &str,
    ) -> Result<PartialValue, OperationError> {
        let schema = self.get_schema();

        // Lookup the attr
        match schema.get_attributes().get(attr) {
            Some(schema_a) => {
                match schema_a.syntax {
                    SyntaxType::Utf8String | SyntaxType::TotpSecret => {
                        Ok(PartialValue::new_utf8(value.to_string()))
                    }
                    SyntaxType::Utf8StringInsensitive
                    | SyntaxType::JwsKeyEs256
                    | SyntaxType::JwsKeyRs256 => Ok(PartialValue::new_iutf8(value)),
                    SyntaxType::Utf8StringIname => Ok(PartialValue::new_iname(value)),
                    SyntaxType::Boolean => PartialValue::new_bools(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid boolean syntax".to_string())
                    }),
                    SyntaxType::SyntaxId => PartialValue::new_syntaxs(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid Syntax syntax".to_string())
                    }),
                    SyntaxType::IndexId => PartialValue::new_indexes(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid Index syntax".to_string())
                    }),
                    SyntaxType::Uuid => {
                        let un = self.name_to_uuid(value).unwrap_or(UUID_DOES_NOT_EXIST);
                        Ok(PartialValue::Uuid(un))
                    }
                    // ⚠️   Any types here need to also be added to update_attributes in
                    // schema.rs for reference type / cache awareness during referential
                    // integrity processing. Exceptions are self-contained value types!
                    SyntaxType::ReferenceUuid
                    | SyntaxType::OauthScopeMap
                    | SyntaxType::Session
                    | SyntaxType::Oauth2Session => {
                        let un = self.name_to_uuid(value).unwrap_or(UUID_DOES_NOT_EXIST);
                        Ok(PartialValue::Refer(un))
                    }
                    SyntaxType::JsonFilter => {
                        PartialValue::new_json_filter_s(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid Filter syntax".to_string())
                        })
                    }
                    SyntaxType::Credential => Ok(PartialValue::new_credential_tag(value)),
                    SyntaxType::SecretUtf8String => Ok(PartialValue::new_secret_str()),
                    SyntaxType::SshKey => Ok(PartialValue::new_sshkey_tag_s(value)),
                    SyntaxType::SecurityPrincipalName => {
                        PartialValue::new_spn_s(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid spn syntax".to_string())
                        })
                    }
                    SyntaxType::Uint32 => PartialValue::new_uint32_str(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid uint32 syntax".to_string())
                    }),
                    SyntaxType::Cid => PartialValue::new_cid_s(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid cid syntax".to_string())
                    }),
                    SyntaxType::NsUniqueId => Ok(PartialValue::new_nsuniqueid_s(value)),
                    SyntaxType::DateTime => PartialValue::new_datetime_s(value).ok_or_else(|| {
                        OperationError::InvalidAttribute(
                            "Invalid DateTime (rfc3339) syntax".to_string(),
                        )
                    }),
                    SyntaxType::EmailAddress => Ok(PartialValue::new_email_address_s(value)),
                    SyntaxType::Url => PartialValue::new_url_s(value).ok_or_else(|| {
                        OperationError::InvalidAttribute(
                            "Invalid Url (whatwg/url) syntax".to_string(),
                        )
                    }),
                    SyntaxType::OauthScope => Ok(PartialValue::new_oauthscope(value)),
                    SyntaxType::PrivateBinary => Ok(PartialValue::PrivateBinary),
                    SyntaxType::IntentToken => PartialValue::new_intenttoken_s(value.to_string())
                        .ok_or_else(|| {
                            OperationError::InvalidAttribute(
                                "Invalid Intent Token ID (uuid) syntax".to_string(),
                            )
                        }),
                    SyntaxType::Passkey => PartialValue::new_passkey_s(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid Passkey UUID syntax".to_string())
                    }),
                    SyntaxType::DeviceKey => {
                        PartialValue::new_devicekey_s(value).ok_or_else(|| {
                            OperationError::InvalidAttribute(
                                "Invalid DeviceKey UUID syntax".to_string(),
                            )
                        })
                    }
                    SyntaxType::UiHint => UiHint::from_str(value)
                        .map(PartialValue::UiHint)
                        .map_err(|()| {
                            OperationError::InvalidAttribute("Invalid uihint syntax".to_string())
                        }),
                }
            }
            None => {
                // No attribute of this name exists - fail fast, there is no point to
                // proceed, as nothing can be satisfied.
                Err(OperationError::InvalidAttributeName(attr.to_string()))
            }
        }
    }

    // In the opposite direction, we can resolve values for presentation
    fn resolve_valueset(&mut self, value: &ValueSet) -> Result<Vec<String>, OperationError> {
        if let Some(r_set) = value.as_refer_set() {
            let v: Result<Vec<_>, _> = r_set
                .iter()
                .copied()
                .map(|ur| {
                    let nv = self.uuid_to_spn(ur)?;
                    match nv {
                        Some(v) => Ok(v.to_proto_string_clone()),
                        None => Ok(uuid_to_proto_string(ur)),
                    }
                })
                .collect();
            v
        } else if let Some(r_map) = value.as_oauthscopemap() {
            let v: Result<Vec<_>, _> = r_map
                .iter()
                .map(|(u, m)| {
                    let nv = self.uuid_to_spn(*u)?;
                    let u = match nv {
                        Some(v) => v.to_proto_string_clone(),
                        None => uuid_to_proto_string(*u),
                    };
                    Ok(format!("{}: {:?}", u, m))
                })
                .collect();
            v
        } else {
            let v: Vec<_> = value.to_proto_string_clone_iter().collect();
            Ok(v)
        }
    }

    fn resolve_valueset_ldap(
        &mut self,
        value: &ValueSet,
        basedn: &str,
    ) -> Result<Vec<Vec<u8>>, OperationError> {
        if let Some(r_set) = value.as_refer_set() {
            let v: Result<Vec<_>, _> = r_set
                .iter()
                .copied()
                .map(|ur| {
                    let rdn = self.uuid_to_rdn(ur)?;
                    Ok(format!("{},{}", rdn, basedn).into_bytes())
                })
                .collect();
            v
        } else if let Some(k_set) = value.as_sshkey_map() {
            let v: Vec<_> = k_set.values().cloned().map(|s| s.into_bytes()).collect();
            Ok(v)
        } else {
            let v: Vec<_> = value
                .to_proto_string_clone_iter()
                .map(|s| s.into_bytes())
                .collect();
            Ok(v)
        }
    }

    /// Pull the domain name from the database
    fn get_db_domain_name(&mut self) -> Result<String, OperationError> {
        self.internal_search_uuid(UUID_DOMAIN_INFO)
            .and_then(|e| {
                trace!(?e);
                e.get_ava_single_iname("domain_name")
                    .map(str::to_string)
                    .ok_or(OperationError::InvalidEntryState)
            })
            .map_err(|e| {
                admin_error!(?e, "Error getting domain name");
                e
            })
    }

    fn get_domain_fernet_private_key(&mut self) -> Result<String, OperationError> {
        self.internal_search_uuid(UUID_DOMAIN_INFO)
            .and_then(|e| {
                e.get_ava_single_secret("fernet_private_key_str")
                    .map(str::to_string)
                    .ok_or(OperationError::InvalidEntryState)
            })
            .map_err(|e| {
                admin_error!(?e, "Error getting domain fernet key");
                e
            })
    }

    fn get_domain_es256_private_key(&mut self) -> Result<Vec<u8>, OperationError> {
        self.internal_search_uuid(UUID_DOMAIN_INFO)
            .and_then(|e| {
                e.get_ava_single_private_binary("es256_private_key_der")
                    .map(|s| s.to_vec())
                    .ok_or(OperationError::InvalidEntryState)
            })
            .map_err(|e| {
                admin_error!(?e, "Error getting domain es256 key");
                e
            })
    }

    // This is a helper to get password badlist.
    fn get_password_badlist(&mut self) -> Result<HashSet<String>, OperationError> {
        self.internal_search_uuid(UUID_SYSTEM_CONFIG)
            .map(|e| match e.get_ava_iter_iutf8("badlist_password") {
                Some(vs_str_iter) => vs_str_iter.map(str::to_string).collect::<HashSet<_>>(),
                None => HashSet::default(),
            })
            .map_err(|e| {
                admin_error!(?e, "Failed to retrieve system configuration");
                e
            })
    }

    fn get_oauth2rs_set(&mut self) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        self.internal_search(filter!(f_eq("class", PVCLASS_OAUTH2_RS.clone(),)))
    }
}

// Actually conduct a search request
// This is the core of the server, as it processes the entire event
// applies all parts required in order and more.
impl<'a> QueryServerTransaction<'a> for QueryServerReadTransaction<'a> {
    type AccessControlsTransactionType = AccessControlsReadTransaction<'a>;
    type BackendTransactionType = BackendReadTransaction<'a>;
    type SchemaTransactionType = SchemaReadTransaction;

    fn get_be_txn(&mut self) -> &mut BackendReadTransaction<'a> {
        &mut self.be_txn
    }

    fn get_schema<'b>(&self) -> &'b SchemaReadTransaction {
        // Strip the lifetime here. Schema is a sub-component of the transaction and is
        // *never* changed excepting in a write TXN, so we want to allow the schema to
        // be borrowed while the rest of the read txn is under a mut.
        unsafe {
            let s = (&self.schema) as *const _;
            &*s
        }
    }

    fn get_accesscontrols(&self) -> &AccessControlsReadTransaction<'a> {
        &self.accesscontrols
    }

    fn get_resolve_filter_cache(
        &mut self,
    ) -> &mut ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>
    {
        &mut self.resolve_filter_cache
    }

    fn get_resolve_filter_cache_and_be_txn(
        &mut self,
    ) -> (
        &mut BackendReadTransaction<'a>,
        &mut ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>,
    ) {
        (&mut self.be_txn, &mut self.resolve_filter_cache)
    }

    fn get_domain_uuid(&self) -> Uuid {
        self.d_info.d_uuid
    }

    fn get_domain_name(&self) -> &str {
        &self.d_info.d_name
    }

    fn get_domain_display_name(&self) -> &str {
        &self.d_info.d_display
    }
}

impl<'a> QueryServerReadTransaction<'a> {
    // Verify the data content of the server is as expected. This will probably
    // call various functions for validation, including possibly plugin
    // verifications.
    pub(crate) fn verify(&mut self) -> Vec<Result<(), ConsistencyError>> {
        // If we fail after backend, we need to return NOW because we can't
        // assert any other faith in the DB states.
        //  * backend
        let be_errs = self.get_be_txn().verify();

        if !be_errs.is_empty() {
            return be_errs;
        }

        //  * in memory schema consistency.
        let sc_errs = self.get_schema().validate();

        if !sc_errs.is_empty() {
            return sc_errs;
        }

        //  * Indexing (req be + sch )
        let idx_errs = self.get_be_txn().verify_indexes();

        if !idx_errs.is_empty() {
            return idx_errs;
        }

        // If anything error to this point we can't trust the verifications below. From
        // here we can just amass results.
        let mut results = Vec::new();

        // Verify all our entries. Weird flex I know, but it's needed for verifying
        // the entry changelogs are consistent to their entries.
        let schema = self.get_schema();

        let filt_all = filter!(f_pres("class"));
        let all_entries = match self.internal_search(filt_all) {
            Ok(a) => a,
            Err(_e) => return vec![Err(ConsistencyError::QueryServerSearchFailure)],
        };

        for e in all_entries {
            e.verify(schema, &mut results)
        }

        // Verify the RUV to the entry changelogs now.
        self.get_be_txn().verify_ruv(&mut results);

        // Ok entries passed, lets move on to the content.
        // Most of our checks are in the plugins, so we let them
        // do their job.

        // Now, call the plugins verification system.
        Plugins::run_verify(self, &mut results);
        // Finished

        results
    }
}

impl<'a> QueryServerTransaction<'a> for QueryServerWriteTransaction<'a> {
    type AccessControlsTransactionType = AccessControlsWriteTransaction<'a>;
    type BackendTransactionType = BackendWriteTransaction<'a>;
    type SchemaTransactionType = SchemaWriteTransaction<'a>;

    fn get_be_txn(&mut self) -> &mut BackendWriteTransaction<'a> {
        &mut self.be_txn
    }

    fn get_schema<'b>(&self) -> &'b SchemaWriteTransaction<'a> {
        // Strip the lifetime here. Schema is a sub-component of the transaction and is
        // *never* changed excepting in a write TXN, so we want to allow the schema to
        // be borrowed while the rest of the read txn is under a mut.
        unsafe {
            let s = (&self.schema) as *const _;
            &*s
        }
    }

    fn get_accesscontrols(&self) -> &AccessControlsWriteTransaction<'a> {
        &self.accesscontrols
    }

    fn get_resolve_filter_cache(
        &mut self,
    ) -> &mut ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>
    {
        &mut self.resolve_filter_cache
    }

    fn get_resolve_filter_cache_and_be_txn(
        &mut self,
    ) -> (
        &mut BackendWriteTransaction<'a>,
        &mut ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>,
    ) {
        (&mut self.be_txn, &mut self.resolve_filter_cache)
    }

    fn get_domain_uuid(&self) -> Uuid {
        self.d_info.d_uuid
    }

    /// Gets the in-memory domain_name element
    fn get_domain_name(&self) -> &str {
        &self.d_info.d_name
    }

    fn get_domain_display_name(&self) -> &str {
        &self.d_info.d_display
    }
}

impl QueryServer {
    pub fn new(be: Backend, schema: Schema, domain_name: String) -> Self {
        let (s_uuid, d_uuid) = {
            let mut wr = be.write();
            let res = (wr.get_db_s_uuid(), wr.get_db_d_uuid());
            #[allow(clippy::expect_used)]
            wr.commit()
                .expect("Critical - unable to commit db_s_uuid or db_d_uuid");
            res
        };

        let pool_size = be.get_pool_size();

        debug!("Server UUID -> {:?}", s_uuid);
        debug!("Domain UUID -> {:?}", d_uuid);
        debug!("Domain Name -> {:?}", domain_name);

        let d_info = Arc::new(CowCell::new(DomainInfo {
            d_uuid,
            d_name: domain_name.clone(),
            // we set the domain_display_name to the configuration file's domain_name
            // here because the database is not started, so we cannot pull it from there.
            d_display: domain_name,
        }));

        let dyngroup_cache = Arc::new(CowCell::new(DynGroupCache::default()));

        let phase = Arc::new(CowCell::new(ServerPhase::Bootstrap));

        // log_event!(log, "Starting query worker ...");

        #[allow(clippy::expect_used)]
        QueryServer {
            phase,
            s_uuid,
            d_info,
            be,
            schema: Arc::new(schema),
            accesscontrols: Arc::new(AccessControls::default()),
            db_tickets: Arc::new(Semaphore::new(pool_size as usize)),
            write_ticket: Arc::new(Semaphore::new(1)),
            resolve_filter_cache: Arc::new(
                ARCacheBuilder::new()
                    .set_size(RESOLVE_FILTER_CACHE_MAX, RESOLVE_FILTER_CACHE_LOCAL)
                    .set_reader_quiesce(true)
                    .build()
                    .expect("Failed to build resolve_filter_cache"),
            ),
            dyngroup_cache,
        }
    }

    pub fn try_quiesce(&self) {
        self.be.try_quiesce();
        self.accesscontrols.try_quiesce();
        self.resolve_filter_cache.try_quiesce();
    }

    pub async fn read(&self) -> QueryServerReadTransaction<'_> {
        // We need to ensure a db conn will be available
        #[allow(clippy::expect_used)]
        let db_ticket = self
            .db_tickets
            .acquire()
            .await
            .expect("unable to acquire db_ticket for qsr");

        QueryServerReadTransaction {
            be_txn: self.be.read(),
            schema: self.schema.read(),
            d_info: self.d_info.read(),
            accesscontrols: self.accesscontrols.read(),
            _db_ticket: db_ticket,
            resolve_filter_cache: self.resolve_filter_cache.read(),
        }
    }

    pub async fn write(&self, curtime: Duration) -> QueryServerWriteTransaction<'_> {
        // Guarantee we are the only writer on the thread pool
        #[allow(clippy::expect_used)]
        let write_ticket = self
            .write_ticket
            .acquire()
            .await
            .expect("unable to acquire writer_ticket for qsw");
        // We need to ensure a db conn will be available
        #[allow(clippy::expect_used)]
        let db_ticket = self
            .db_tickets
            .acquire()
            .await
            .expect("unable to acquire db_ticket for qsw");

        let schema_write = self.schema.write();
        let mut be_txn = self.be.write();
        let d_info = self.d_info.write();
        let phase = self.phase.write();

        #[allow(clippy::expect_used)]
        let ts_max = be_txn
            .get_db_ts_max(curtime)
            .expect("Unable to get db_ts_max");
        let cid = Cid::new_lamport(self.s_uuid, curtime, &ts_max);

        QueryServerWriteTransaction {
            // I think this is *not* needed, because commit is mut self which should
            // take ownership of the value, and cause the commit to "only be run
            // once".
            //
            // The committed flag is however used for abort-specific code in drop
            // which today I don't think we have ... yet.
            committed: false,
            phase,
            d_info,
            curtime,
            cid,
            be_txn,
            schema: schema_write,
            accesscontrols: self.accesscontrols.write(),
            changed_schema: false,
            changed_acp: false,
            changed_oauth2: false,
            changed_domain: false,
            changed_uuid: HashSet::new(),
            _db_ticket: db_ticket,
            _write_ticket: write_ticket,
            resolve_filter_cache: self.resolve_filter_cache.read(),
            dyngroup_cache: self.dyngroup_cache.write(),
        }
    }

    pub async fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        let mut r_txn = self.read().await;
        r_txn.verify()
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    pub(crate) fn get_curtime(&self) -> Duration {
        self.curtime
    }

    pub(crate) fn get_dyngroup_cache(&mut self) -> &mut DynGroupCache {
        &mut self.dyngroup_cache
    }

    #[instrument(level = "debug", name = "reload_schema", skip(self))]
    fn reload_schema(&mut self) -> Result<(), OperationError> {
        // supply entries to the writable schema to reload from.
        // find all attributes.
        let filt = filter!(f_eq("class", PVCLASS_ATTRIBUTETYPE.clone()));
        let res = self.internal_search(filt).map_err(|e| {
            admin_error!("reload schema internal search failed {:?}", e);
            e
        })?;
        // load them.
        let attributetypes: Result<Vec<_>, _> =
            res.iter().map(|e| SchemaAttribute::try_from(e)).collect();
        let attributetypes = attributetypes.map_err(|e| {
            admin_error!("reload schema attributetypes {:?}", e);
            e
        })?;

        self.schema.update_attributes(attributetypes).map_err(|e| {
            admin_error!("reload schema update attributetypes {:?}", e);
            e
        })?;

        // find all classes
        let filt = filter!(f_eq("class", PVCLASS_CLASSTYPE.clone()));
        let res = self.internal_search(filt).map_err(|e| {
            admin_error!("reload schema internal search failed {:?}", e);
            e
        })?;
        // load them.
        let classtypes: Result<Vec<_>, _> = res.iter().map(|e| SchemaClass::try_from(e)).collect();
        let classtypes = classtypes.map_err(|e| {
            admin_error!("reload schema classtypes {:?}", e);
            e
        })?;

        self.schema.update_classes(classtypes).map_err(|e| {
            admin_error!("reload schema update classtypes {:?}", e);
            e
        })?;

        // validate.
        let valid_r = self.schema.validate();

        // Translate the result.
        if valid_r.is_empty() {
            // Now use this to reload the backend idxmeta
            trace!("Reloading idxmeta ...");
            self.be_txn
                .update_idxmeta(self.schema.reload_idxmeta())
                .map_err(|e| {
                    admin_error!("reload schema update idxmeta {:?}", e);
                    e
                })
        } else {
            // Log the failures?
            admin_error!("Schema reload failed -> {:?}", valid_r);
            Err(OperationError::ConsistencyError(valid_r))
        }?;

        // TODO: Clear the filter resolve cache.
        // currently we can't do this because of the limits of types with arccache txns. The only
        // thing this impacts is if something in indexed though, and the backend does handle
        // incorrectly indexed items correctly.

        // Trigger reloads on services that require post-schema reloads.
        // Mainly this is plugins.
        if *self.phase >= ServerPhase::SchemaReady {
            DynGroup::reload(self)?;
        }

        Ok(())
    }

    fn reload_accesscontrols(&mut self) -> Result<(), OperationError> {
        // supply entries to the writable access controls to reload from.
        // This has to be done in FOUR passes - one for each type!
        //
        // Note, we have to do the search, parse, then submit here, because of the
        // requirement to have the write query server reference in the parse stage - this
        // would cause a rust double-borrow if we had AccessControls to try to handle
        // the entry lists themself.
        trace!("ACP reload started ...");

        // Update search
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACS.clone()),
            f_andnot(f_eq("acp_enable", PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!(
                err = ?e,
                "reload accesscontrols internal search failed",
            );
            e
        })?;
        let search_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlSearch::try_from(self, e))
            .collect();

        let search_acps = search_acps.map_err(|e| {
            admin_error!(err = ?e, "Unable to parse search accesscontrols");
            e
        })?;

        self.accesscontrols
            .update_search(search_acps)
            .map_err(|e| {
                admin_error!(err = ?e, "Failed to update search accesscontrols");
                e
            })?;
        // Update create
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACC.clone()),
            f_andnot(f_eq("acp_enable", PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!(
                err = ?e,
                "reload accesscontrols internal search failed"
            );
            e
        })?;
        let create_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlCreate::try_from(self, e))
            .collect();

        let create_acps = create_acps.map_err(|e| {
            admin_error!(err = ?e, "Unable to parse create accesscontrols");
            e
        })?;

        self.accesscontrols
            .update_create(create_acps)
            .map_err(|e| {
                admin_error!(err = ?e, "Failed to update create accesscontrols");
                e
            })?;
        // Update modify
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACM.clone()),
            f_andnot(f_eq("acp_enable", PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!("reload accesscontrols internal search failed {:?}", e);
            e
        })?;
        let modify_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlModify::try_from(self, e))
            .collect();

        let modify_acps = modify_acps.map_err(|e| {
            admin_error!("Unable to parse modify accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols
            .update_modify(modify_acps)
            .map_err(|e| {
                admin_error!("Failed to update modify accesscontrols {:?}", e);
                e
            })?;
        // Update delete
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACD.clone()),
            f_andnot(f_eq("acp_enable", PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!("reload accesscontrols internal search failed {:?}", e);
            e
        })?;
        let delete_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlDelete::try_from(self, e))
            .collect();

        let delete_acps = delete_acps.map_err(|e| {
            admin_error!("Unable to parse delete accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols.update_delete(delete_acps).map_err(|e| {
            admin_error!("Failed to update delete accesscontrols {:?}", e);
            e
        })
    }

    fn get_db_domain_display_name(&mut self) -> Result<String, OperationError> {
        self.internal_search_uuid(UUID_DOMAIN_INFO)
            .and_then(|e| {
                trace!(?e);
                e.get_ava_single_utf8("domain_display_name")
                    .map(str::to_string)
                    .ok_or(OperationError::InvalidEntryState)
            })
            .map_err(|e| {
                admin_error!(?e, "Error getting domain display name");
                e
            })
    }

    /// Pulls the domain name from the database and updates the DomainInfo data in memory
    #[instrument(level = "debug", skip_all)]
    fn reload_domain_info(&mut self) -> Result<(), OperationError> {
        let domain_name = self.get_db_domain_name()?;
        let display_name = self.get_db_domain_display_name()?;
        let mut_d_info = self.d_info.get_mut();
        if mut_d_info.d_name != domain_name {
            admin_warn!(
                "Using domain name from the database {} - was {} in memory",
                domain_name,
                mut_d_info.d_name,
            );
            admin_warn!(
                    "If you think this is an error, see https://kanidm.github.io/kanidm/stable/administrivia.html#rename-the-domain"
                );
            mut_d_info.d_name = domain_name;
        }
        mut_d_info.d_display = display_name;
        Ok(())
    }

    /// Initiate a domain display name change process. This isn't particularly scary
    /// because it's just a wibbly human-facing thing, not used for secure
    /// activities (yet)
    pub fn set_domain_display_name(&mut self, new_domain_name: &str) -> Result<(), OperationError> {
        let modl = ModifyList::new_purge_and_set(
            "domain_display_name",
            Value::new_utf8(new_domain_name.to_string()),
        );
        let udi = PVUUID_DOMAIN_INFO.clone();
        let filt = filter_all!(f_eq("uuid", udi));
        self.internal_modify(&filt, &modl)
    }

    /// Initiate a domain rename process. This is generally an internal function but it's
    /// exposed to the cli for admins to be able to initiate the process.
    pub fn domain_rename(&mut self, new_domain_name: &str) -> Result<(), OperationError> {
        // We can't use the d_info struct here, because this has the database version of the domain
        // name, not the in memory (config) version. We need to accept the domain's
        // new name from the caller so we can change this.
        unsafe { self.domain_rename_inner(new_domain_name) }
    }

    /// # Safety
    /// This is UNSAFE because while it may change the domain name, it doesn't update
    /// the running configured version of the domain name that is resident to the
    /// query server.
    ///
    /// Currently it's only used to test what happens if we rename the domain and how
    /// that impacts spns, but in the future we may need to reconsider how this is
    /// approached, especially if we have a domain re-name replicated to us. It could
    /// be that we end up needing to have this as a cow cell or similar?
    pub(crate) unsafe fn domain_rename_inner(
        &mut self,
        new_domain_name: &str,
    ) -> Result<(), OperationError> {
        let modl = ModifyList::new_purge_and_set("domain_name", Value::new_iname(new_domain_name));
        let udi = PVUUID_DOMAIN_INFO.clone();
        let filt = filter_all!(f_eq("uuid", udi));
        self.internal_modify(&filt, &modl)
    }

    pub fn reindex(&mut self) -> Result<(), OperationError> {
        // initiate a be reindex here. This could have been from first run checking
        // the versions, or it could just be from the cli where an admin needs to do an
        // indexing.
        self.be_txn.reindex()
    }

    fn force_schema_reload(&mut self) {
        self.changed_schema = true;
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn upgrade_reindex(&mut self, v: i64) -> Result<(), OperationError> {
        self.be_txn.upgrade_reindex(v)
    }

    pub fn get_changed_uuids(&self) -> &HashSet<Uuid> {
        &self.changed_uuid
    }

    pub fn get_changed_ouath2(&self) -> bool {
        self.changed_oauth2
    }

    pub fn get_changed_domain(&self) -> bool {
        self.changed_domain
    }

    fn set_phase(&mut self, phase: ServerPhase) {
        *self.phase = phase
    }

    #[instrument(level = "info", skip_all)]
    pub fn commit(mut self) -> Result<(), OperationError> {
        // This could be faster if we cache the set of classes changed
        // in an operation so we can check if we need to do the reload or not
        //
        // Reload the schema from qs.
        if self.changed_schema {
            self.reload_schema()?;
        }
        // Determine if we need to update access control profiles
        // based on any modifications that have occurred.
        // IF SCHEMA CHANGED WE MUST ALSO RELOAD!!! IE if schema had an attr removed
        // that we rely on we MUST fail this here!!
        if self.changed_schema || self.changed_acp {
            self.reload_accesscontrols()?;
        } else {
            // On a reload the cache is dropped, otherwise we tell accesscontrols
            // to drop anything related that was changed.
            // self.accesscontrols
            //    .invalidate_related_cache(self.changed_uuid.into_inner().as_slice())
        }

        if self.changed_domain {
            self.reload_domain_info()?;
        }

        // Now destructure the transaction ready to reset it.
        let QueryServerWriteTransaction {
            committed,
            phase,
            mut be_txn,
            schema,
            d_info,
            accesscontrols,
            cid,
            dyngroup_cache,
            ..
        } = self;
        debug_assert!(!committed);

        // Write the cid to the db. If this fails, we can't assume replication
        // will be stable, so return if it fails.
        be_txn.set_db_ts_max(cid.ts)?;
        // Validate the schema as we just loaded it.
        let r = schema.validate();

        if r.is_empty() {
            // Schema has been validated, so we can go ahead and commit it with the be
            // because both are consistent.
            schema
                .commit()
                .map(|_| d_info.commit())
                .map(|_| phase.commit())
                .map(|_| dyngroup_cache.commit())
                .and_then(|_| accesscontrols.commit())
                .and_then(|_| be_txn.commit())
        } else {
            Err(OperationError::ConsistencyError(r))
        }
        // Audit done
    }
}

#[cfg(test)]
mod tests {

    use crate::prelude::*;

    #[qs_test]
    async fn test_name_to_uuid(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let t_uuid = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson1")),
                ("uuid", Value::Uuid(t_uuid)),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            ),])
            .is_ok());

        // Name doesn't exist
        let r1 = server_txn.name_to_uuid("testpers");
        assert!(r1.is_err());
        // Name doesn't exist (not syntax normalised)
        let r2 = server_txn.name_to_uuid("tEsTpErS");
        assert!(r2.is_err());
        // Name does exist
        let r3 = server_txn.name_to_uuid("testperson1");
        assert!(r3 == Ok(t_uuid));
        // Name is not syntax normalised (but exists)
        let r4 = server_txn.name_to_uuid("tEsTpErSoN1");
        assert!(r4 == Ok(t_uuid));
    }

    #[qs_test]
    async fn test_external_id_to_uuid(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let t_uuid = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("extensibleobject")),
                ("uuid", Value::Uuid(t_uuid)),
                ("sync_external_id", Value::new_iutf8("uid=testperson"))
            ),])
            .is_ok());

        // Name doesn't exist
        let r1 = server_txn.sync_external_id_to_uuid("tobias");
        assert!(r1 == Ok(None));
        // Name doesn't exist (not syntax normalised)
        let r2 = server_txn.sync_external_id_to_uuid("tObIAs");
        assert!(r2 == Ok(None));
        // Name does exist
        let r3 = server_txn.sync_external_id_to_uuid("uid=testperson");
        assert!(r3 == Ok(Some(t_uuid)));
        // Name is not syntax normalised (but exists)
        let r4 = server_txn.sync_external_id_to_uuid("uId=TeStPeRsOn");
        assert!(r4 == Ok(Some(t_uuid)));
    }

    #[qs_test]
    async fn test_uuid_to_spn(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Name doesn't exist
        let r1 = server_txn.uuid_to_spn(uuid!("bae3f507-e6c3-44ba-ad01-f8ff1083534a"));
        // There is nothing.
        assert!(r1 == Ok(None));
        // Name does exist
        let r3 = server_txn.uuid_to_spn(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"));
        println!("{:?}", r3);
        assert!(r3.unwrap().unwrap() == Value::new_spn_str("testperson1", "example.com"));
        // Name is not syntax normalised (but exists)
        let r4 = server_txn.uuid_to_spn(uuid!("CC8E95B4-C24F-4D68-BA54-8BED76F63930"));
        assert!(r4.unwrap().unwrap() == Value::new_spn_str("testperson1", "example.com"));
    }

    #[qs_test]
    async fn test_uuid_to_rdn(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson1"))
        );
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Name doesn't exist
        let r1 = server_txn.uuid_to_rdn(uuid!("bae3f507-e6c3-44ba-ad01-f8ff1083534a"));
        // There is nothing.
        assert!(r1.unwrap() == "uuid=bae3f507-e6c3-44ba-ad01-f8ff1083534a");
        // Name does exist
        let r3 = server_txn.uuid_to_rdn(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"));
        println!("{:?}", r3);
        assert!(r3.unwrap() == "spn=testperson1@example.com");
        // Uuid is not syntax normalised (but exists)
        let r4 = server_txn.uuid_to_rdn(uuid!("CC8E95B4-C24F-4D68-BA54-8BED76F63930"));
        assert!(r4.unwrap() == "spn=testperson1@example.com");
    }

    #[qs_test]
    async fn test_clone_value(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // test attr not exist
        let r1 = server_txn.clone_value("tausau", "naoeutnhaou");

        assert!(r1.is_err());

        // test attr not-normalised (error)
        // test attr not-reference
        let r2 = server_txn.clone_value("NaMe", "NaMe");

        assert!(r2.is_err());

        // test attr reference
        let r3 = server_txn.clone_value("member", "testperson1");

        assert!(r3 == Ok(Value::Refer(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))));

        // test attr reference already resolved.
        let r4 = server_txn.clone_value("member", "cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        debug!("{:?}", r4);
        assert!(r4 == Ok(Value::Refer(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))));
    }

    #[qs_test]
    async fn test_dynamic_schema_class(server: &QueryServer) {
        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("testclass")),
            ("name", Value::new_iname("testobj1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            )
        );

        // Class definition
        let e_cd = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("classtype")),
            ("classname", Value::new_iutf8("testclass")),
            (
                "uuid",
                Value::Uuid(uuid!("cfcae205-31c3-484b-8ced-667d1709c5e3"))
            ),
            ("description", Value::new_utf8s("Test Class")),
            ("may", Value::new_iutf8("name"))
        );
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // Add a new class.
        let ce_class = CreateEvent::new_internal(vec![e_cd.clone()]);
        assert!(server_txn.create(&ce_class).is_ok());
        // Trying to add it now should fail.
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // Add the class to an object
        // should work
        let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_work).is_ok());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // delete the class
        let de_class = unsafe {
            DeleteEvent::new_internal_invalid(filter!(f_eq(
                "classname",
                PartialValue::new_class("testclass")
            )))
        };
        assert!(server_txn.delete(&de_class).is_ok());
        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // Trying to add now should fail
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());
        // Search our entry
        let testobj1 = server_txn
            .internal_search_uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            .expect("failed");
        assert!(testobj1.attribute_equality("class", &PartialValue::new_class("testclass")));

        // Should still be good
        server_txn.commit().expect("should not fail");
        // Commit.
    }

    #[qs_test]
    async fn test_dynamic_schema_attr(server: &QueryServer) {
        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("extensibleobject")),
            ("name", Value::new_iname("testobj1")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("testattr", Value::new_utf8s("test"))
        );

        // Attribute definition
        let e_ad = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("attributetype")),
            (
                "uuid",
                Value::Uuid(uuid!("cfcae205-31c3-484b-8ced-667d1709c5e3"))
            ),
            ("attributename", Value::new_iutf8("testattr")),
            ("description", Value::new_utf8s("Test Attribute")),
            ("multivalue", Value::new_bool(false)),
            ("unique", Value::new_bool(false)),
            ("syntax", Value::new_syntaxs("UTF8STRING").expect("syntax"))
        );

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // Add a new attribute.
        let ce_attr = CreateEvent::new_internal(vec![e_ad.clone()]);
        assert!(server_txn.create(&ce_attr).is_ok());
        // Trying to add it now should fail. (use extensible object)
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // Add the attr to an object
        // should work
        let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_work).is_ok());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // delete the attr
        let de_attr = unsafe {
            DeleteEvent::new_internal_invalid(filter!(f_eq(
                "attributename",
                PartialValue::new_iutf8("testattr")
            )))
        };
        assert!(server_txn.delete(&de_attr).is_ok());
        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // Trying to add now should fail
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());
        // Search our attribute - should FAIL
        let filt = filter!(f_eq("testattr", PartialValue::new_utf8s("test")));
        assert!(server_txn.internal_search(filt).is_err());
        // Search the entry - the attribute will still be present
        // even if we can't search on it.
        let testobj1 = server_txn
            .internal_search_uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            .expect("failed");
        assert!(testobj1.attribute_equality("testattr", &PartialValue::new_utf8s("test")));

        server_txn.commit().expect("should not fail");
        // Commit.
    }
}
