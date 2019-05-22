// Access Control Profiles
//
// This is a pretty important and security sensitive part of the code - it's
// responsible for making sure that who is allowed to do what is enforced, as
// well as who is *not* allowed to do what.
//
// A detailed design can be found in access-profiles-and-security.

//
// This part of the server really has a few parts
// - the ability to parse access profile structures into real ACP structs
// - the ability to apply sets of ACP's to entries for coarse actions (IE
//   search.
// - the ability to turn an entry into a partial-entry for results send
//   requirements (also search).
//

use concread::cowcell::{CowCell, CowCellReadTxn, CowCellWriteTxn};
use std::collections::BTreeMap;
use std::convert::TryFrom;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryValid};
use crate::error::OperationError;
use crate::filter::{Filter, FilterValid};
use crate::proto_v1::Filter as ProtoFilter;
use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};

use crate::event::SearchEvent;

// =========================================================================
// PARSE ENTRY TO ACP, AND ACP MANAGEMENT
// =========================================================================

#[derive(Debug, Clone)]
pub struct AccessControlSearch {
    acp: AccessControlProfile,
    attrs: Vec<String>,
}

impl AccessControlSearch {
    pub fn try_from(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", "access_control_search") {
            audit_log!(audit, "class access_control_search not present.");
            return Err(OperationError::InvalidACPState);
        }

        let attrs = try_audit!(
            audit,
            value
                .get_ava("acp_search_attr")
                .ok_or(OperationError::InvalidACPState)
                .map(|vs: &Vec<String>| vs.clone())
        );

        let acp = AccessControlProfile::try_from(audit, qs, value)?;

        Ok(AccessControlSearch {
            acp: acp,
            attrs: attrs,
        })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: &str,
        receiver: Filter<FilterValid>,
        targetscope: Filter<FilterValid>,
        attrs: &str,
    ) -> Self {
        AccessControlSearch {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid: uuid.to_string(),
                receiver: receiver,
                targetscope: targetscope,
            },
            attrs: attrs.split_whitespace().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlDelete {
    acp: AccessControlProfile,
}

impl AccessControlDelete {
    pub fn try_from(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", "access_control_delete") {
            audit_log!(audit, "class access_control_delete not present.");
            return Err(OperationError::InvalidACPState);
        }

        Ok(AccessControlDelete {
            acp: AccessControlProfile::try_from(audit, qs, value)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlCreate {
    acp: AccessControlProfile,
    classes: Vec<String>,
    attrs: Vec<String>,
}

impl AccessControlCreate {
    pub fn try_from(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", "access_control_create") {
            audit_log!(audit, "class access_control_create not present.");
            return Err(OperationError::InvalidACPState);
        }

        let attrs = value
            .get_ava("acp_create_attr")
            .map(|vs: &Vec<String>| vs.clone())
            .unwrap_or_else(|| Vec::new());

        let classes = value
            .get_ava("acp_create_class")
            .map(|vs: &Vec<String>| vs.clone())
            .unwrap_or_else(|| Vec::new());

        Ok(AccessControlCreate {
            acp: AccessControlProfile::try_from(audit, qs, value)?,
            classes: classes,
            attrs: attrs,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlModify {
    acp: AccessControlProfile,
    classes: Vec<String>,
    presattrs: Vec<String>,
    remattrs: Vec<String>,
}

impl AccessControlModify {
    pub fn try_from(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", "access_control_modify") {
            audit_log!(audit, "class access_control_modify not present.");
            return Err(OperationError::InvalidACPState);
        }

        let presattrs = value
            .get_ava("acp_modify_presentattr")
            .map(|vs: &Vec<String>| vs.clone())
            .unwrap_or_else(|| Vec::new());

        let remattrs = value
            .get_ava("acp_modify_removedattr")
            .map(|vs: &Vec<String>| vs.clone())
            .unwrap_or_else(|| Vec::new());

        let classes = value
            .get_ava("acp_modify_class")
            .map(|vs: &Vec<String>| vs.clone())
            .unwrap_or_else(|| Vec::new());

        Ok(AccessControlModify {
            acp: AccessControlProfile::try_from(audit, qs, value)?,
            classes: classes,
            presattrs: presattrs,
            remattrs: remattrs,
        })
    }
}

#[derive(Debug, Clone)]
struct AccessControlProfile {
    name: String,
    uuid: String,
    receiver: Filter<FilterValid>,
    targetscope: Filter<FilterValid>,
}

impl AccessControlProfile {
    fn try_from(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Assert we have class access_control_profile
        if !value.attribute_value_pres("class", "access_control_profile") {
            audit_log!(audit, "class access_control_profile not present.");
            return Err(OperationError::InvalidACPState);
        }

        // copy name
        let name = try_audit!(
            audit,
            value
                .get_ava_single("name")
                .ok_or(OperationError::InvalidACPState)
        );
        // copy uuid
        let uuid = value.get_uuid();
        // receiver, and turn to real filter
        let receiver_raw = try_audit!(
            audit,
            value
                .get_ava_single("acp_receiver")
                .ok_or(OperationError::InvalidACPState)
        );
        // targetscope, and turn to real filter
        let targetscope_raw = try_audit!(
            audit,
            value
                .get_ava_single("acp_targetscope")
                .ok_or(OperationError::InvalidACPState)
        );

        audit_log!(audit, "RAW receiver {:?}", receiver_raw);
        let receiver_f: ProtoFilter = try_audit!(
            audit,
            serde_json::from_str(receiver_raw.as_str())
                .map_err(|_| OperationError::InvalidACPState)
        );
        let receiver_i = try_audit!(audit, Filter::from_rw(audit, &receiver_f, qs));
        let receiver = try_audit!(
            audit,
            receiver_i
                .validate(qs.get_schema())
                .map_err(|e| OperationError::SchemaViolation(e))
        );

        audit_log!(audit, "RAW tscope {:?}", targetscope_raw);
        let targetscope_f: ProtoFilter = try_audit!(
            audit,
            serde_json::from_str(targetscope_raw.as_str())
                .map_err(|_| OperationError::InvalidACPState)
        );
        let targetscope_i = try_audit!(audit, Filter::from_rw(audit, &targetscope_f, qs));
        let targetscope = try_audit!(
            audit,
            targetscope_i
                .validate(qs.get_schema())
                .map_err(|e| OperationError::SchemaViolation(e))
        );

        Ok(AccessControlProfile {
            name: name.clone(),
            uuid: uuid.clone(),
            receiver: receiver,
            targetscope: targetscope,
        })
    }
}

// =========================================================================
// ACP transactions and management for server bits.
// =========================================================================

#[derive(Debug, Clone)]
struct AccessControlsInner {
    // What is the correct key here?
    acps_search: BTreeMap<String, AccessControlSearch>,
    acps_create: BTreeMap<String, AccessControlCreate>,
    acps_modify: BTreeMap<String, AccessControlModify>,
    acps_delete: BTreeMap<String, AccessControlDelete>,
}

impl AccessControlsInner {
    fn new() -> Self {
        AccessControlsInner {
            acps_search: BTreeMap::new(),
            acps_create: BTreeMap::new(),
            acps_modify: BTreeMap::new(),
            acps_delete: BTreeMap::new(),
        }
    }
}

pub struct AccessControls {
    inner: CowCell<AccessControlsInner>,
}

pub trait AccessControlsTransaction {
    fn get_inner(&self) -> &AccessControlsInner;

    // Contains all the way to eval acps to entries
    fn search_filter_entries(
        &self,
        audit: &mut AuditScope,
        se: &SearchEvent,
        entries: Vec<Entry<EntryValid, EntryCommitted>>,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        // If this is an internal search, return our working set.
        if se.is_internal() {
            return Ok(entries);
        }

        // First get the set of acps that apply to this receiver

        // Now for that set, apply them to the entries.

        // unimplemented!();
        Ok(entries)
    }

    fn search_filter_entry_attributes(
        &self,
        entries: &Vec<Entry<EntryValid, EntryCommitted>>,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        unimplemented!();
    }
}

pub struct AccessControlsWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, AccessControlsInner>,
}

impl<'a> AccessControlsWriteTransaction<'a> {
    fn get_inner_mut(&mut self) -> &mut AccessControlsInner {
        &mut self.inner
    }

    // We have a method to update each set, so that if an error
    // occurs we KNOW it's an error, rather than using errors as
    // part of the logic (IE try-parse-fail method).
    pub fn update_search(&mut self, acps: Vec<AccessControlSearch>) -> Result<(), OperationError> {
        // Clear the existing tree. We don't care that we are wiping it
        // because we have the transactions to protect us from errors
        // to allow rollbacks.
        let mut inner = self.get_inner_mut();
        inner.acps_search.clear();
        for acp in acps {
            let uuid = acp.acp.uuid.clone();
            inner
                .acps_search
                .insert(uuid, acp)
                .ok_or(OperationError::InvalidACPState)?;
        }
        Ok(())
    }

    pub fn update_create(&mut self, acps: Vec<AccessControlCreate>) -> Result<(), OperationError> {
        let mut inner = self.get_inner_mut();
        inner.acps_create.clear();
        for acp in acps {
            let uuid = acp.acp.uuid.clone();
            inner
                .acps_create
                .insert(uuid, acp)
                .ok_or(OperationError::InvalidACPState)?;
        }
        Ok(())
    }

    pub fn update_modify(&mut self, acps: Vec<AccessControlModify>) -> Result<(), OperationError> {
        let mut inner = self.get_inner_mut();
        inner.acps_modify.clear();
        for acp in acps {
            let uuid = acp.acp.uuid.clone();
            inner
                .acps_modify
                .insert(uuid, acp)
                .ok_or(OperationError::InvalidACPState)?;
        }
        Ok(())
    }

    pub fn update_delete(&mut self, acps: Vec<AccessControlDelete>) -> Result<(), OperationError> {
        let mut inner = self.get_inner_mut();
        inner.acps_delete.clear();
        for acp in acps {
            let uuid = acp.acp.uuid.clone();
            inner
                .acps_delete
                .insert(uuid, acp)
                .ok_or(OperationError::InvalidACPState)?;
        }
        Ok(())
    }

    pub fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();
        Ok(())
    }
}

impl<'a> AccessControlsTransaction for AccessControlsWriteTransaction<'a> {
    fn get_inner(&self) -> &AccessControlsInner {
        &self.inner
    }
}

// =========================================================================
// ACP operations (Should this actually be on the ACP's themself?
// =========================================================================

pub struct AccessControlsReadTransaction {
    inner: CowCellReadTxn<AccessControlsInner>,
}

impl AccessControlsTransaction for AccessControlsReadTransaction {
    fn get_inner(&self) -> &AccessControlsInner {
        &self.inner
    }
}

// =========================================================================
// ACP transaction operations
// =========================================================================

impl AccessControls {
    pub fn new() -> Self {
        AccessControls {
            inner: CowCell::new(AccessControlsInner::new()),
        }
    }

    pub fn read(&self) -> AccessControlsReadTransaction {
        AccessControlsReadTransaction {
            inner: self.inner.read(),
        }
    }

    pub fn write(&self) -> AccessControlsWriteTransaction {
        AccessControlsWriteTransaction {
            inner: self.inner.write(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::access::{
        AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlProfile,
        AccessControlSearch, AccessControls, AccessControlsTransaction,
    };
    use crate::audit::AuditScope;
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    // use crate::server::QueryServerWriteTransaction;
    use std::convert::TryFrom;

    use crate::event::SearchEvent;
    // use crate::filter::Filter;
    // use crate::proto_v1::Filter as ProtoFilter;

    macro_rules! acp_from_entry_err {
        (
            $audit:expr,
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str($e).expect("json failure");
            let ev1 = unsafe { e1.to_valid_committed() };

            let r1 = <$type>::try_from($audit, $qs, &ev1);
            assert!(r1.is_err());
        }};
    }

    macro_rules! acp_from_entry_ok {
        (
            $audit:expr,
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str($e).expect("json failure");
            let ev1 = unsafe { e1.to_valid_committed() };

            let r1 = <$type>::try_from($audit, $qs, &ev1);
            assert!(r1.is_ok());
            r1.unwrap()
        }};
    }

    #[test]
    fn test_access_acp_parser() {
        run_test!(|qs: &QueryServer, audit: &mut AuditScope| {
            // Test parsing entries to acp. There so no point testing schema violations
            // because the schema system is well tested an robust. Instead we target
            // entry misconfigurations, such as missing classes required.

            // Generally, we are testing the *positive* cases here, because schema
            // really protects us *a lot* here, but it's nice to have defence and
            // layers of validation.

            let qs_write = qs.write();

            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
                    }
                }"#,
                AccessControlProfile
            );

            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
                    }
                }"#,
                AccessControlProfile
            );

            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [""],
                        "acp_targetscope": [""]
                    }
                }"#,
                AccessControlProfile
            );

            // "\"Self\""
            acp_from_entry_ok!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
                AccessControlProfile
            );
        })
    }

    #[test]
    fn test_access_acp_delete_parser() {
        run_test!(|qs: &QueryServer, audit: &mut AuditScope| {
            let qs_write = qs.write();

            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
                AccessControlDelete
            );

            acp_from_entry_ok!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_delete"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
                AccessControlDelete
            );
        })
    }

    #[test]
    fn test_access_acp_search_parser() {
        run_test!(|qs: &QueryServer, audit: &mut AuditScope| {
            // Test that parsing search access controls works.
            let qs_write = qs.write();

            // Missing class acp
            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_search"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_search_attr": ["name", "class"]
                    }
                }"#,
                AccessControlSearch
            );

            // Missing class acs
            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_search_attr": ["name", "class"]
                    }
                }"#,
                AccessControlSearch
            );

            // Missing attr acp_search_attr
            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_search"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
                AccessControlSearch
            );

            // All good!
            acp_from_entry_ok!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_search"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_search_attr": ["name", "class"]
                    }
                }"#,
                AccessControlSearch
            );
        })
    }

    #[test]
    fn test_access_acp_modify_parser() {
        run_test!(|qs: &QueryServer, audit: &mut AuditScope| {
            // Test that parsing modify access controls works.
            let qs_write = qs.write();

            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_modify_removedattr": ["name"],
                        "acp_modify_presentattr": ["name"],
                        "acp_modify_class": ["object"]
                    }
                }"#,
                AccessControlModify
            );

            acp_from_entry_ok!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_modify"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
                AccessControlModify
            );

            acp_from_entry_ok!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_modify"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_modify_removedattr": ["name"],
                        "acp_modify_presentattr": ["name"],
                        "acp_modify_class": ["object"]
                    }
                }"#,
                AccessControlModify
            );
        })
    }

    #[test]
    fn test_access_acp_create_parser() {
        run_test!(|qs: &QueryServer, audit: &mut AuditScope| {
            // Test that parsing create access controls works.
            let qs_write = qs.write();

            acp_from_entry_err!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_create_class": ["object"],
                        "acp_create_attr": ["name"]
                    }
                }"#,
                AccessControlCreate
            );

            acp_from_entry_ok!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_create"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
                AccessControlCreate
            );

            acp_from_entry_ok!(
                audit,
                &qs_write,
                r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_create"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_create_class": ["object"],
                        "acp_create_attr": ["name"]
                    }
                }"#,
                AccessControlCreate
            );
        })
    }

    #[test]
    fn test_access_acp_compound_parser() {
        run_test!(|qs: &QueryServer, audit: &mut AuditScope| {
            // Test that parsing compound access controls works. This means that
            // given a single &str, we can evaluate all types from a single record.
            // This is valid, and could exist, IE a rule to allow create, search and modify
            // over a single scope.
            let qs_write = qs.write();

            let e: &str = r#"{
                    "valid": null,
                    "state": null,
                    "attrs": {
                        "class": [
                            "object",
                            "access_control_profile",
                            "access_control_create",
                            "access_control_delete",
                            "access_control_modify",
                            "access_control_search"
                        ],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_targetscope": [
                            "{\"Eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_search_attr": ["name"],
                        "acp_create_class": ["object"],
                        "acp_create_attr": ["name"],
                        "acp_modify_removedattr": ["name"],
                        "acp_modify_presentattr": ["name"],
                        "acp_modify_class": ["object"]
                    }
                }"#;

            acp_from_entry_ok!(audit, &qs_write, e, AccessControlCreate);
            acp_from_entry_ok!(audit, &qs_write, e, AccessControlDelete);
            acp_from_entry_ok!(audit, &qs_write, e, AccessControlModify);
            acp_from_entry_ok!(audit, &qs_write, e, AccessControlSearch);
        })
    }

    macro_rules! test_acp_search {
        (
            $se:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::new();
            let mut acw = ac.write();
            acw.update_search($controls);
            let acw = acw;

            let mut audit = AuditScope::new("test_acp_search");
            let res = acw.search_filter_entries(&mut audit, $se, $entries);
            // should be ok, and same as expect.
            assert!(res.expect("op failed") == $expect);
        }};
    }

    #[test]
    fn test_access_internal_search() {
        // Test that an internal search bypasses ACS
        let se = SearchEvent::new_internal(filter!(f_pres("class")));

        let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
                }
                }"#,
        )
        .expect("json failure");
        let ev1 = unsafe { e1.to_valid_committed() };

        let expect = vec![ev1.clone()];
        let entries = vec![ev1];

        // This acp basically is "allow access to stuff, but not this".
        test_acp_search!(
            &se,
            vec![unsafe {
                AccessControlSearch::from_raw(
                    "test_acp",
                    "d38640c4-0254-49f9-99b7-8ba7d0233f3d",
                    unsafe { filter_valid!(f_pres("class")) }, // apply to all people
                    unsafe { filter_valid!(f_pres("nomatchy")) }, // apply to none - ie no allowed results
                    "name", // allow to this attr, but we don't eval this.
                )
            }],
            entries,
            expect
        );
    }

    #[test]
    fn test_access_enforce_search() {
        // Test that entries from a search are reduced by acps

        // First, we need to resolve the ACS based on SE data. This means
        // that filter self-params need to be updated and evaluated.
        //
        // Importantly, self is resolved via the event, not the QS, so we avoid
        // many of the loop-style issues we had to parse/update acps in the first place.

    }

    #[test]
    fn test_access_enforce_search_attrs() {
        // Test that attributes are correctly limited.
    }
}
