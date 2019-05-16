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
use std::convert::TryFrom;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryValid};
use crate::error::OperationError;
use crate::filter::{Filter, FilterValid};
use crate::proto_v1::Filter as ProtoFilter;
use crate::server::{QueryServerReadTransaction, QueryServerTransaction};

// =========================================================================
// PARSE ENTRY TO ACP, AND ACP MANAGEMENT
// =========================================================================

struct AccessControlSearch {
    acp: AccessControlProfile,
    attrs: Vec<String>,
}

impl
    TryFrom<(
        &mut AuditScope,
        &QueryServerTransaction,
        &Entry<EntryValid, EntryCommitted>,
    )> for AccessControlSearch
{
    type Error = OperationError;

    fn try_from(
        (audit, qs, value): (
            &mut AuditScope,
            &QueryServerTransaction,
            &Entry<EntryValid, EntryCommitted>,
        ),
    ) -> Result<Self, Self::Error> {

        let attrs = try_audit!(audit, value.get_ava("acp_search_attr")
            .ok_or(OperationError::InvalidACPState)
            .map(|vs: &Vec<String>| {
                vs.clone()
            }));

        let acp = AccessControlProfile::try_from(audit, qs, value)?;

        Ok(AccessControlSearch {
            acp: acp,
            attrs: attrs,
        })
    }
}


struct AccessControlDelete {
    acp: AccessControlProfile,
}

impl
    TryFrom<(
        &mut AuditScope,
        &QueryServerTransaction,
        &Entry<EntryValid, EntryCommitted>,
    )> for AccessControlDelete
{
    type Error = OperationError;

    fn try_from(
        (audit, qs, value): (
            &mut AuditScope,
            &QueryServerTransaction,
            &Entry<EntryValid, EntryCommitted>,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(AccessControlDelete {
            acp: AccessControlProfile::try_from(audit, qs, value)?
        })
    }
}

struct AccessControlCreate {
    acp: AccessControlProfile,
    classes: Vec<String>,
    attrs: Vec<String>,
}

struct AccessControlModify {
    acp: AccessControlProfile,
    classes: Vec<String>,
    presattrs: Vec<String>,
    remattrs: Vec<String>,
}

struct AccessControlProfile {
    name: String,
    uuid: String,
    receiver: Filter<FilterValid>,
    targetscope: Filter<FilterValid>,
}

impl AccessControlProfile
{
    fn try_from(
            audit: &mut AuditScope,
            qs: &QueryServerTransaction,
            value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Assert we have class access_control_profile
        if !value.attribute_value_pres("class", "access_control_profile") {
            audit_log!(audit, "class access_control_profile not present.");
            return Err(OperationError::InvalidACPState);
        }

        // copy name
        let name = try_audit!(audit, value
            .get_ava_single("name")
            .ok_or(OperationError::InvalidACPState));
        // copy uuid
        let uuid = value.get_uuid();
        // receiver, and turn to real filter
        let receiver_raw = try_audit!(audit, value
            .get_ava_single("acp_receiver")
            .ok_or(OperationError::InvalidACPState));
        // targetscope, and turn to real filter
        let targetscope_raw = try_audit!(audit, value
            .get_ava_single("acp_targetscope")
            .ok_or(OperationError::InvalidACPState));

        audit_log!(audit, "RAW receiver {:?}", receiver_raw);
        let receiver_f: ProtoFilter = try_audit!(audit, serde_json::from_str(receiver_raw.as_str())
            .map_err(|_| OperationError::InvalidACPState));
        let receiver_i = try_audit!(audit, Filter::from_ro(audit, &receiver_f, qs));
        let receiver = try_audit!(audit, receiver_i
            .validate(qs.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e)));

        audit_log!(audit, "RAW tscope {:?}", targetscope_raw);
        let targetscope_f: ProtoFilter = try_audit!(audit, serde_json::from_str(targetscope_raw.as_str())
            .map_err(|_| OperationError::InvalidACPState));
        let targetscope_i = try_audit!(audit, Filter::from_ro(audit, &targetscope_f, qs));
        let targetscope = try_audit!(audit, targetscope_i
            .validate(qs.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e)));

        Ok(AccessControlProfile {
            name: name.clone(),
            uuid: uuid.clone(),
            receiver: receiver,
            targetscope: targetscope,
        })
    }
}

// =========================================================================
// ACP operations
// =========================================================================

// =========================================================================
// ACP transactions and management for server.
// =========================================================================

// =========================================================================
// ACP transaction operations
// =========================================================================

#[cfg(test)]
mod tests {
    use crate::entry::{Entry, EntryCommitted, EntryValid, EntryNew, EntryInvalid};
    use crate::access::AccessControlProfile;
    use std::convert::TryFrom;
    use crate::audit::AuditScope;
    use crate::server::QueryServerTransaction;

    use crate::proto_v1::Filter as ProtoFilter;

    macro_rules! acp_from_entry_err{
        (
            $audit:expr,
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str($e).expect("json failure");
            let ev1 = unsafe { e1.to_valid_committed() };

            let r1 = <$type>::try_from(
                $audit, $qs, &ev1
            );
            assert!(r1.is_err());
        }};
    }

    macro_rules! acp_from_entry_ok{
        (
            $audit:expr,
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str($e).expect("json failure");
            let ev1 = unsafe { e1.to_valid_committed() };

            let r1 = <$type>::try_from(
                $audit, $qs, &ev1
            );
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

            let qs_read = qs.read();

            acp_from_entry_err!(audit, &qs_read,
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

            acp_from_entry_err!(audit, &qs_read,
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

            acp_from_entry_err!(audit, &qs_read,
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
            acp_from_entry_ok!(audit, &qs_read,
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
                        ]
                    }
                }"#,
                AccessControlProfile
            );
        })
    }

    #[test]
    fn test_access_acp_search_parser() {
        run_test!(|qs: &QueryServer, audit: &mut AuditScope| {
            // Test that parsing search access controls works.
        })
    }
}

