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

use concread::collections::bptree::*;
use kanidm_proto::v1::Filter as ProtoFilter;
use kanidm_proto::v1::OperationError;
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryReduced, EntryValid};
use crate::filter::{Filter, FilterValid};
use crate::modify::Modify;
use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
use crate::value::PartialValue;

use crate::event::{CreateEvent, DeleteEvent, EventOrigin, ModifyEvent, SearchEvent};

lazy_static! {
    static ref CLASS_ACS: PartialValue = PartialValue::new_class("access_control_search");
    static ref CLASS_ACC: PartialValue = PartialValue::new_class("access_control_create");
    static ref CLASS_ACD: PartialValue = PartialValue::new_class("access_control_delete");
    static ref CLASS_ACM: PartialValue = PartialValue::new_class("access_control_modify");
    static ref CLASS_ACP: PartialValue = PartialValue::new_class("access_control_profile");
}

// =========================================================================
// PARSE ENTRY TO ACP, AND ACP MANAGEMENT
// =========================================================================

#[derive(Debug, Clone)]
pub struct AccessControlSearch {
    acp: AccessControlProfile,
    // TODO: Should this change to Value? May help to reduce transformations during processing.
    attrs: BTreeSet<String>,
}

impl AccessControlSearch {
    pub fn try_from(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        value: &Entry<EntryValid, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_value_pres("class", &CLASS_ACS) {
            audit_log!(audit, "class access_control_search not present.");
            return Err(OperationError::InvalidACPState(
                "Missing access_control_search".to_string(),
            ));
        }

        let attrs = try_audit!(
            audit,
            value.get_ava_set_string("acp_search_attr").ok_or_else(|| {
                OperationError::InvalidACPState("Missing acp_search_attr".to_string())
            })
        );

        let acp = AccessControlProfile::try_from(audit, qs, value)?;

        Ok(AccessControlSearch { acp, attrs })
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
                uuid: Uuid::parse_str(uuid).unwrap(),
                receiver,
                targetscope,
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
        if !value.attribute_value_pres("class", &CLASS_ACD) {
            audit_log!(audit, "class access_control_delete not present.");
            return Err(OperationError::InvalidACPState(
                "Missing access_control_delete".to_string(),
            ));
        }

        Ok(AccessControlDelete {
            acp: AccessControlProfile::try_from(audit, qs, value)?,
        })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: &str,
        receiver: Filter<FilterValid>,
        targetscope: Filter<FilterValid>,
    ) -> Self {
        AccessControlDelete {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid: Uuid::parse_str(uuid).unwrap(),
                receiver,
                targetscope,
            },
        }
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
        if !value.attribute_value_pres("class", &CLASS_ACC) {
            audit_log!(audit, "class access_control_create not present.");
            return Err(OperationError::InvalidACPState(
                "Missing access_control_create".to_string(),
            ));
        }

        let attrs = value
            .get_ava_opt_string("acp_create_attr")
            .unwrap_or_else(Vec::new);

        let classes = value
            .get_ava_opt_string("acp_create_class")
            .unwrap_or_else(Vec::new);

        Ok(AccessControlCreate {
            acp: AccessControlProfile::try_from(audit, qs, value)?,
            classes,
            attrs,
        })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: &str,
        receiver: Filter<FilterValid>,
        targetscope: Filter<FilterValid>,
        classes: &str,
        attrs: &str,
    ) -> Self {
        AccessControlCreate {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid: Uuid::parse_str(uuid).unwrap(),
                receiver,
                targetscope,
            },
            classes: classes.split_whitespace().map(|s| s.to_string()).collect(),
            attrs: attrs.split_whitespace().map(|s| s.to_string()).collect(),
        }
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
        if !value.attribute_value_pres("class", &CLASS_ACM) {
            audit_log!(audit, "class access_control_modify not present.");
            return Err(OperationError::InvalidACPState(
                "Missing access_control_modify".to_string(),
            ));
        }

        let presattrs = value
            .get_ava_opt_string("acp_modify_presentattr")
            .unwrap_or_else(Vec::new);

        let remattrs = value
            .get_ava_opt_string("acp_modify_removedattr")
            .unwrap_or_else(Vec::new);

        let classes = value
            .get_ava_opt_string("acp_modify_class")
            .unwrap_or_else(Vec::new);

        Ok(AccessControlModify {
            acp: AccessControlProfile::try_from(audit, qs, value)?,
            classes,
            presattrs,
            remattrs,
        })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: &str,
        receiver: Filter<FilterValid>,
        targetscope: Filter<FilterValid>,
        presattrs: &str,
        remattrs: &str,
        classes: &str,
    ) -> Self {
        AccessControlModify {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid: Uuid::parse_str(uuid).unwrap(),
                receiver,
                targetscope,
            },
            classes: classes.split_whitespace().map(|s| s.to_string()).collect(),
            presattrs: presattrs
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            remattrs: remattrs.split_whitespace().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct AccessControlProfile {
    name: String,
    uuid: Uuid,
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
        if !value.attribute_value_pres("class", &CLASS_ACP) {
            audit_log!(audit, "class access_control_profile not present.");
            return Err(OperationError::InvalidACPState(
                "Missing access_control_profile".to_string(),
            ));
        }

        // copy name
        let name = try_audit!(
            audit,
            value
                .get_ava_single_str("name")
                .ok_or_else(|| OperationError::InvalidACPState("Missing name".to_string()))
        )
        .to_string();
        // copy uuid
        let uuid = *value.get_uuid();
        // receiver, and turn to real filter
        let receiver_f: ProtoFilter = try_audit!(
            audit,
            value
                .get_ava_single_protofilter("acp_receiver")
                .ok_or_else(|| OperationError::InvalidACPState("Missing acp_receiver".to_string()))
        );
        // targetscope, and turn to real filter
        let targetscope_f: ProtoFilter = try_audit!(
            audit,
            value
                .get_ava_single_protofilter("acp_targetscope")
                .ok_or_else(|| OperationError::InvalidACPState(
                    "Missing acp_targetscope".to_string()
                ))
        );

        let receiver_i = try_audit!(audit, Filter::from_rw(audit, &receiver_f, qs));
        let receiver = try_audit!(
            audit,
            receiver_i
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)
        );

        let targetscope_i = try_audit!(audit, Filter::from_rw(audit, &targetscope_f, qs));
        let targetscope = try_audit!(
            audit,
            targetscope_i
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)
        );

        Ok(AccessControlProfile {
            name,
            uuid,
            receiver,
            targetscope,
        })
    }
}

// =========================================================================
// ACP transactions and management for server bits.
// =========================================================================

pub struct AccessControls {
    // inner: CowCell<AccessControlsInner>,
    acps_search: BptreeMap<Uuid, AccessControlSearch>,
    acps_create: BptreeMap<Uuid, AccessControlCreate>,
    acps_modify: BptreeMap<Uuid, AccessControlModify>,
    acps_delete: BptreeMap<Uuid, AccessControlDelete>,
}

pub trait AccessControlsTransaction {
    fn get_search(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlSearch>;
    fn get_create(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlCreate>;
    fn get_modify(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlModify>;
    fn get_delete(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlDelete>;

    // Contains all the way to eval acps to entries
    fn search_filter_entries(
        &self,
        audit: &mut AuditScope,
        se: &SearchEvent,
        entries: Vec<Entry<EntryValid, EntryCommitted>>,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        audit_log!(audit, "Access check for event: {:?}", se);

        // If this is an internal search, return our working set.
        let rec_entry: &Entry<EntryValid, EntryCommitted> = match &se.event.origin {
            EventOrigin::Internal => {
                audit_log!(audit, "Internal operation, bypassing access check");
                // No need to check ACS
                return Ok(entries);
            }
            EventOrigin::User(e) => &e,
        };

        // Some useful references we'll use for the remainder of the operation
        let search_state = self.get_search();

        // First get the set of acps that apply to this receiver
        let related_acp: Vec<&AccessControlSearch> = search_state
            .iter()
            .filter_map(|(_, acs)| {
                // Now resolve the receiver filter
                // Okay, so in filter resolution, the primary error case
                // is that we have a non-user in the event. We have already
                // checked for this above BUT we should still check here
                // properly just in case.
                //
                // In this case, we assume that if the event is internal
                // that the receiver can NOT match because it has no selfuuid
                // and can as a result, never return true. This leads to this
                // acp not being considered in that case ... which should never
                // happen because we already bypassed internal ops above!
                //
                // A possible solution is to change the filter resolve function
                // such that it takes an entry, rather than an event, but that
                // would create issues in search.
                let f_val = acs.acp.receiver.clone();
                match f_val.resolve(&se.event, None) {
                    Ok(f_res) => {
                        if rec_entry.entry_match_no_index(&f_res) {
                            Some(acs)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        audit_log!(
                            audit,
                            "A internal filter was passed for resolution!?!? {:?}",
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        related_acp.iter().for_each(|racp| {
            audit_log!(audit, "Related acs -> {:?}", racp.acp.name);
        });

        // Get the set of attributes requested by this se filter. This is what we are
        // going to access check.
        let requested_attrs: BTreeSet<&str> = se.filter_orig.get_attr_set();

        // For each entry
        let allowed_entries: Vec<Entry<EntryValid, EntryCommitted>> = entries
            .into_iter()
            .filter(|e| {
                // For each acp
                let allowed_attrs: BTreeSet<&str> = related_acp
                    .iter()
                    .filter_map(|acs| {
                        let f_val = acs.acp.targetscope.clone();
                        match f_val.resolve(&se.event, None) {
                            Ok(f_res) => {
                                // if it applies
                                if e.entry_match_no_index(&f_res) {
                                    audit_log!(
                                        audit,
                                        "entry {:?} matches acs {:?}",
                                        e.get_uuid(),
                                        acs
                                    );
                                    // add search_attrs to allowed.
                                    let r: Vec<&str> =
                                        acs.attrs.iter().map(|s| s.as_str()).collect();
                                    Some(r)
                                } else {
                                    audit_log!(
                                        audit,
                                        "entry {:?} DOES NOT match acs {:?}",
                                        e.get_uuid(),
                                        acs
                                    );
                                    None
                                }
                            }
                            Err(e) => {
                                audit_log!(
                                    audit,
                                    "A internal filter was passed for resolution!?!? {:?}",
                                    e
                                );
                                None
                            }
                        }
                    })
                    .flatten()
                    .collect();

                audit_log!(audit, "-- for entry         --> {:?}", e.get_uuid());
                audit_log!(audit, "allowed attributes   --> {:?}", allowed_attrs);
                audit_log!(audit, "requested attributes --> {:?}", requested_attrs);

                // is attr set a subset of allowed set?
                // true -> entry is allowed in result set
                // false -> the entry is not allowed to be searched by this entity, so is
                //          excluded.
                let decision = requested_attrs.is_subset(&allowed_attrs);
                audit_log!(audit, "search attr decision --> {:?}", decision);
                decision
            })
            .collect();

        Ok(allowed_entries)
    }

    fn search_filter_entry_attributes(
        &self,
        audit: &mut AuditScope,
        se: &SearchEvent,
        entries: Vec<Entry<EntryValid, EntryCommitted>>,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        /*
         * Super similar to above (could even re-use some parts). Given a set of entries,
         * reduce the attribute sets on them to "what is visible". This is ONLY called on
         * the server edge, such that clients only see what they can, but internally,
         * impersonate and such actually still get the whole entry back as not to break
         * modify and co.
         */
        audit_log!(audit, "Access check and reduce for event: {:?}", se);

        // If this is an internal search, do nothing. How this occurs in this
        // interface is beyond me ....
        let rec_entry: &Entry<EntryValid, EntryCommitted> = match &se.event.origin {
            EventOrigin::Internal => {
                if cfg!(test) {
                    audit_log!(audit, "TEST: Internal search in external interface - allowing due to cfg test ...");
                    // In tests we just push everything back.
                    return Ok(entries
                        .into_iter()
                        .map(|e| unsafe { e.into_reduced() })
                        .collect());
                } else {
                    // In production we can't risk leaking data here, so we return
                    // empty sets.
                    audit_log!(audit, "IMPOSSIBLE STATE: Internal search in external interface?! Returning empty for safety.");
                    // No need to check ACS
                    return Ok(Vec::new());
                }
            }
            EventOrigin::User(e) => &e,
        };

        // Some useful references we'll use for the remainder of the operation
        let search_state = self.get_search();

        // Get the relevant acps for this receiver.
        let related_acp: Vec<&AccessControlSearch> = search_state
            .iter()
            .filter_map(|(_, acs)| {
                let f_val = acs.acp.receiver.clone();
                match f_val.resolve(&se.event, None) {
                    Ok(f_res) => {
                        // Is our user covered by this acs?
                        if rec_entry.entry_match_no_index(&f_res) {
                            // If so, let's check if the attr request is relevant.

                            // If we have a requested attr set, are any of them
                            // in the attrs this acs covers?
                            let acs_target_attrs = match &se.attrs {
                                Some(r_attrs) => acs.attrs.intersection(r_attrs).count(),
                                // All attrs requested, do nothing.
                                None => acs.attrs.len(),
                            };

                            // There is nothing in the ACS (not possible) or
                            // no overlap between the requested set and this acs, so it's
                            // not worth evaling.
                            if acs_target_attrs == 0 {
                                None
                            } else {
                                Some(acs)
                            }
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        audit_log!(
                            audit,
                            "A internal filter was passed for resolution!?!? {:?}",
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        related_acp.iter().for_each(|racp| {
            audit_log!(audit, "Related acs -> {:?}", racp.acp.name);
        });

        // Build a reference set from the req_attrs
        let req_attrs: Option<BTreeSet<_>> = se
            .attrs
            .as_ref()
            .map(|vs| vs.iter().map(|s| s.as_str()).collect());

        //  For each entry
        let allowed_entries: Vec<Entry<EntryReduced, EntryCommitted>> = entries
            .into_iter()
            .map(|e| {
                // Get the set of attributes you can see
                let allowed_attrs: BTreeSet<&str> = related_acp
                    .iter()
                    .filter_map(|acs| {
                        let f_val = acs.acp.targetscope.clone();
                        match f_val.resolve(&se.event, None) {
                            Ok(f_res) => {
                                // if it applies
                                if e.entry_match_no_index(&f_res) {
                                    audit_log!(
                                        audit,
                                        "entry {:?} matches acs {:?}",
                                        e.get_uuid(),
                                        acs
                                    );
                                    // add search_attrs to allowed.
                                    let r: Vec<&str> =
                                        acs.attrs.iter().map(|s| s.as_str()).collect();
                                    Some(r)
                                } else {
                                    audit_log!(
                                        audit,
                                        "entry {:?} DOES NOT match acs {:?}",
                                        e.get_uuid(),
                                        acs
                                    );
                                    None
                                }
                            }
                            Err(e) => {
                                audit_log!(
                                    audit,
                                    "A internal filter was passed for resolution!?!? {:?}",
                                    e
                                );
                                None
                            }
                        }
                    })
                    .flatten()
                    .collect();

                // Remove all others that are present on the entry.
                audit_log!(audit, "-- for entry         --> {:?}", e.get_uuid());
                audit_log!(audit, "requested attributes --> {:?}", req_attrs);
                audit_log!(audit, "allowed attributes   --> {:?}", allowed_attrs);

                // Remove anything that wasn't requested.
                let f_allowed_attrs: BTreeSet<&str> = match &req_attrs {
                    Some(v) => allowed_attrs.intersection(&v).copied().collect(),
                    None => allowed_attrs,
                };

                // Now purge the attrs that are NOT in this.
                e.reduce_attributes(f_allowed_attrs)
            })
            .collect();
        Ok(allowed_entries)
    }

    fn modify_allow_operation(
        &self,
        audit: &mut AuditScope,
        me: &ModifyEvent,
        entries: &[Entry<EntryValid, EntryCommitted>],
    ) -> Result<bool, OperationError> {
        audit_log!(audit, "Access check for event: {:?}", me);

        let rec_entry: &Entry<EntryValid, EntryCommitted> = match &me.event.origin {
            EventOrigin::Internal => {
                // No need to check ACS
                return Ok(true);
            }
            EventOrigin::User(e) => &e,
        };

        // Some useful references we'll use for the remainder of the operation
        let modify_state = self.get_modify();

        // Pre-check if the no-no purge class is present
        let disallow = me.modlist.iter().fold(false, |acc, m| {
            if acc {
                acc
            } else {
                match m {
                    Modify::Purged(a) => a == "class",
                    _ => false,
                }
            }
        });
        if disallow {
            audit_log!(audit, "Disallowing purge class in modification");
            return Ok(false);
        }

        // Find the acps that relate to the caller.
        let related_acp: Vec<&AccessControlModify> = modify_state
            .iter()
            .filter_map(|(_, acs)| {
                let f_val = acs.acp.receiver.clone();
                match f_val.resolve(&me.event, None) {
                    Ok(f_res) => {
                        if rec_entry.entry_match_no_index(&f_res) {
                            Some(acs)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        audit_log!(
                            audit,
                            "A internal filter was passed for resolution!?!? {:?}",
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        related_acp.iter().for_each(|racp| {
            audit_log!(audit, "Related acs -> {:?}", racp.acp.name);
        });

        // build two sets of "requested pres" and "requested rem"
        let requested_pres: BTreeSet<&str> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Present(a, _) => Some(a.as_str()),
                _ => None,
            })
            .collect();

        let requested_rem: BTreeSet<&str> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Removed(a, _) => Some(a.as_str()),
                Modify::Purged(a) => Some(a.as_str()),
                _ => None,
            })
            .collect();

        // Build the set of classes that we to work on, only in terms of "addition". To remove
        // I think we have no limit, but ... william of the future may find a problem with this
        // policy.
        let requested_classes: BTreeSet<&str> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Present(a, v) => {
                    if a.as_str() == "class" {
                        // Here we have an option<&str> which could mean there is a risk of
                        // a malicious entity attempting to trick us by masking class mods
                        // in non-iutf8 types. However, the server first won't respect their
                        // existance, and second, we would have failed the mod at schema checking
                        // earlier in the process as these were not correctly type. As a result
                        // we can trust these to be correct here and not to be "None".
                        Some(v.to_str_unwrap())
                    } else {
                        None
                    }
                }
                Modify::Removed(a, v) => {
                    if a.as_str() == "class" {
                        Some(v.to_str_unwrap())
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();

        audit_log!(audit, "Requested present set: {:?}", requested_pres);
        audit_log!(audit, "Requested remove set: {:?}", requested_rem);
        audit_log!(audit, "Requested class set: {:?}", requested_classes);

        let r = entries.iter().fold(true, |acc, e| {
            if !acc {
                false
            } else {
                // For this entry, find the acp's that apply to it from the
                // set that apply to the entry that is performing the operation
                let scoped_acp: Vec<&AccessControlModify> = related_acp
                    .iter()
                    .filter_map(|acm: &&AccessControlModify| {
                        // We are continually compiling and using these
                        // in a tight loop, so this is a possible oppurtunity
                        // to cache or handle these filters better - filter compiler
                        // cache maybe?
                        let f_val = acm.acp.targetscope.clone();
                        match f_val.resolve(&me.event, None) {
                            Ok(f_res) => {
                                if e.entry_match_no_index(&f_res) {
                                    Some(*acm)
                                } else {
                                    None
                                }
                            }
                            Err(e) => {
                                audit_log!(
                                    audit,
                                    "A internal filter was passed for resolution!?!? {:?}",
                                    e
                                );
                                None
                            }
                        }
                    })
                    .collect();
                // Build the sets of classes, pres and rem we are allowed to modify, extend
                // or use based on the set of matched acps.
                let allowed_pres: BTreeSet<&str> = scoped_acp
                    .iter()
                    .flat_map(|acp| acp.presattrs.iter().map(|v| v.as_str()))
                    .collect();

                let allowed_rem: BTreeSet<&str> = scoped_acp
                    .iter()
                    .flat_map(|acp| acp.remattrs.iter().map(|v| v.as_str()))
                    .collect();

                let allowed_classes: BTreeSet<&str> = scoped_acp
                    .iter()
                    .flat_map(|acp| acp.classes.iter().map(|v| v.as_str()))
                    .collect();

                // Now check all the subsets are true. Remember, purge class
                // is already checked above.

                if !requested_pres.is_subset(&allowed_pres) {
                    audit_log!(audit, "requested_pres is not a subset of allowed");
                    audit_log!(audit, "{:?} !⊆ {:?}", requested_pres, allowed_pres);
                    return false;
                }
                if !requested_rem.is_subset(&allowed_rem) {
                    audit_log!(audit, "requested_rem is not a subset of allowed");
                    audit_log!(audit, "{:?} !⊆ {:?}", requested_rem, allowed_rem);
                    return false;
                }
                if !requested_classes.is_subset(&allowed_classes) {
                    audit_log!(audit, "requested_classes is not a subset of allowed");
                    audit_log!(audit, "{:?} !⊆ {:?}", requested_classes, allowed_classes);
                    return false;
                }
                true
            } // if acc == false
        });
        Ok(r)
    }

    fn create_allow_operation(
        &self,
        audit: &mut AuditScope,
        ce: &CreateEvent,
        entries: &[Entry<EntryInvalid, EntryNew>],
    ) -> Result<bool, OperationError> {
        audit_log!(audit, "Access check for event: {:?}", ce);

        let rec_entry: &Entry<EntryValid, EntryCommitted> = match &ce.event.origin {
            EventOrigin::Internal => {
                // No need to check ACS
                return Ok(true);
            }
            EventOrigin::User(e) => &e,
        };

        // Some useful references we'll use for the remainder of the operation
        let create_state = self.get_create();

        // Find the acps that relate to the caller.
        let related_acp: Vec<&AccessControlCreate> = create_state
            .iter()
            .filter_map(|(_, acs)| {
                let f_val = acs.acp.receiver.clone();
                match f_val.resolve(&ce.event, None) {
                    Ok(f_res) => {
                        if rec_entry.entry_match_no_index(&f_res) {
                            Some(acs)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        audit_log!(
                            audit,
                            "A internal filter was passed for resolution!?!? {:?}",
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        audit_log!(audit, "Related acc -> {:?}", related_acp);

        // For each entry
        let r = entries.iter().fold(true, |acc, e| {
            if !acc {
                // We have already failed, move on.
                false
            } else {
                // Build the set of requested classes and attrs here.
                let create_attrs: BTreeSet<&str> = e.get_ava_names();
                // If this is empty, we make an empty set, which is fine because
                // the empty class set despite matching is_subset, will have the
                // following effect:
                // * there is no class on entry, so schema will fail
                // * plugin-base will add object to give a class, but excess
                //   attrs will cause fail (could this be a weakness?)
                // * class is a "may", so this could be empty in the rules, so
                //   if the accr is empty this would not be a true subset,
                //   so this would "fail", but any content in the accr would
                //   have to be validated.
                //
                // I still think if this is None, we should just fail here ...
                // because it shouldn't be possible to match.

                let create_classes: BTreeSet<&str> = match e.get_ava_set_str("class") {
                    Some(s) => s,
                    None => {
                        audit_log!(audit, "Class set failed to build - corrupted entry?");
                        return false;
                    }
                };

                related_acp.iter().fold(false, |r_acc, accr| {
                    if r_acc {
                        // Already allowed, continue.
                        r_acc
                    } else {
                        // Check to see if allowed.
                        let f_val = accr.acp.targetscope.clone();
                        match f_val.resolve(&ce.event, None) {
                            Ok(f_res) => {
                                if e.entry_match_no_index(&f_res) {
                                    audit_log!(audit, "entry {:?} matches acs {:?}", e, accr);
                                    // It matches, so now we have to check attrs and classes.
                                    // Remember, we have to match ALL requested attrs
                                    // and classes to pass!
                                    let allowed_attrs: BTreeSet<&str> =
                                        accr.attrs.iter().map(|s| s.as_str()).collect();
                                    let allowed_classes: BTreeSet<&str> =
                                        accr.classes.iter().map(|s| s.as_str()).collect();

                                    if !create_attrs.is_subset(&allowed_attrs) {
                                        audit_log!(
                                            audit,
                                            "create_attrs is not a subset of allowed"
                                        );
                                        audit_log!(
                                            audit,
                                            "{:?} !⊆ {:?}",
                                            create_attrs,
                                            allowed_attrs
                                        );
                                        return false;
                                    }
                                    if !create_classes.is_subset(&allowed_classes) {
                                        audit_log!(
                                            audit,
                                            "create_classes is not a subset of allowed"
                                        );
                                        audit_log!(
                                            audit,
                                            "{:?} !⊆ {:?}",
                                            create_classes,
                                            allowed_classes
                                        );
                                        return false;
                                    }

                                    true
                                } else {
                                    audit_log!(
                                        audit,
                                        "entry {:?} DOES NOT match acs {:?}",
                                        e,
                                        accr
                                    );
                                    // Does not match, fail this rule.
                                    false
                                }
                            }
                            Err(e) => {
                                audit_log!(
                                    audit,
                                    "A internal filter was passed for resolution!?!? {:?}",
                                    e
                                );
                                // Default to failing here.
                                false
                            }
                        } // match
                    }
                })
            }
            //      Find the set of related acps for this entry.
            //
            //      For each "created" entry.
            //          If the created entry is 100% allowed by this acp
            //          IE: all attrs to be created AND classes match classes
            //              allow
            //          if no acp allows, fail operation.
        });

        Ok(r)
    }

    fn delete_allow_operation(
        &self,
        audit: &mut AuditScope,
        de: &DeleteEvent,
        entries: &[Entry<EntryValid, EntryCommitted>],
    ) -> Result<bool, OperationError> {
        audit_log!(audit, "Access check for event: {:?}", de);

        let rec_entry: &Entry<EntryValid, EntryCommitted> = match &de.event.origin {
            EventOrigin::Internal => {
                // No need to check ACS
                return Ok(true);
            }
            EventOrigin::User(e) => &e,
        };

        // Some useful references we'll use for the remainder of the operation
        let delete_state = self.get_delete();

        // Find the acps that relate to the caller.
        let related_acp: Vec<&AccessControlDelete> = delete_state
            .iter()
            .filter_map(|(_, acs)| {
                let f_val = acs.acp.receiver.clone();
                match f_val.resolve(&de.event, None) {
                    Ok(f_res) => {
                        if rec_entry.entry_match_no_index(&f_res) {
                            Some(acs)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        audit_log!(
                            audit,
                            "A internal filter was passed for resolution!?!? {:?}",
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        related_acp.iter().for_each(|racp| {
            audit_log!(audit, "Related acs -> {:?}", racp.acp.name);
        });

        // For each entry
        let r = entries.iter().fold(true, |acc, e| {
            if !acc {
                // Any false, denies the whole operation.
                false
            } else {
                related_acp.iter().fold(false, |r_acc, acd| {
                    if r_acc {
                        // If something allowed us to delete, skip doing silly work.
                        r_acc
                    } else {
                        let f_val = acd.acp.targetscope.clone();
                        match f_val.resolve(&de.event, None) {
                            Ok(f_res) => {
                                if e.entry_match_no_index(&f_res) {
                                    audit_log!(
                                        audit,
                                        "entry {:?} matches acs {:?}",
                                        e.get_uuid(),
                                        acd
                                    );
                                    // It matches, so we can delete this!
                                    true
                                } else {
                                    audit_log!(
                                        audit,
                                        "entry {:?} DOES NOT match acs {:?}",
                                        e.get_uuid(),
                                        acd
                                    );
                                    // Does not match, fail.
                                    false
                                }
                            }
                            Err(e) => {
                                audit_log!(
                                    audit,
                                    "A internal filter was passed for resolution!?!? {:?}",
                                    e
                                );
                                // Default to failing here.
                                false
                            }
                        } // match
                    } // else
                }) // fold related_acp
            } // if/else
        });
        Ok(r)
    }
}

pub struct AccessControlsWriteTransaction<'a> {
    // inner: CowCellWriteTxn<'a, AccessControlsInner>,
    acps_search: BptreeMapWriteTxn<'a, Uuid, AccessControlSearch>,
    acps_create: BptreeMapWriteTxn<'a, Uuid, AccessControlCreate>,
    acps_modify: BptreeMapWriteTxn<'a, Uuid, AccessControlModify>,
    acps_delete: BptreeMapWriteTxn<'a, Uuid, AccessControlDelete>,
}

impl<'a> AccessControlsWriteTransaction<'a> {
    // We have a method to update each set, so that if an error
    // occurs we KNOW it's an error, rather than using errors as
    // part of the logic (IE try-parse-fail method).
    pub fn update_search(&mut self, acps: Vec<AccessControlSearch>) -> Result<(), OperationError> {
        // Clear the existing tree. We don't care that we are wiping it
        // because we have the transactions to protect us from errors
        // to allow rollbacks.
        self.acps_search.clear();
        for acp in acps {
            let uuid = acp.acp.uuid;
            self.acps_search.insert(uuid, acp);
        }
        self.acps_search.compact();
        Ok(())
    }

    pub fn update_create(&mut self, acps: Vec<AccessControlCreate>) -> Result<(), OperationError> {
        self.acps_create.clear();
        for acp in acps {
            let uuid = acp.acp.uuid;
            self.acps_create.insert(uuid, acp);
        }
        self.acps_create.compact();
        Ok(())
    }

    pub fn update_modify(&mut self, acps: Vec<AccessControlModify>) -> Result<(), OperationError> {
        self.acps_modify.clear();
        for acp in acps {
            let uuid = acp.acp.uuid;
            self.acps_modify.insert(uuid, acp);
        }
        self.acps_modify.compact();
        Ok(())
    }

    pub fn update_delete(&mut self, acps: Vec<AccessControlDelete>) -> Result<(), OperationError> {
        self.acps_delete.clear();
        for acp in acps {
            let uuid = acp.acp.uuid;
            self.acps_delete.insert(uuid, acp);
        }
        // We could consider compact here ...
        self.acps_delete.compact();
        Ok(())
    }

    pub fn commit(self) -> Result<(), OperationError> {
        let AccessControlsWriteTransaction {
            acps_search,
            acps_create,
            acps_modify,
            acps_delete,
        } = self;

        acps_search.commit();
        acps_create.commit();
        acps_modify.commit();
        acps_delete.commit();

        Ok(())
    }
}

impl<'a> AccessControlsTransaction for AccessControlsWriteTransaction<'a> {
    fn get_search(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlSearch> {
        self.acps_search.to_snapshot()
    }

    fn get_create(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlCreate> {
        self.acps_create.to_snapshot()
    }

    fn get_modify(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlModify> {
        self.acps_modify.to_snapshot()
    }

    fn get_delete(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlDelete> {
        self.acps_delete.to_snapshot()
    }
}

// =========================================================================
// ACP operations (Should this actually be on the ACP's themself?
// =========================================================================

pub struct AccessControlsReadTransaction {
    acps_search: BptreeMapReadTxn<Uuid, AccessControlSearch>,
    acps_create: BptreeMapReadTxn<Uuid, AccessControlCreate>,
    acps_modify: BptreeMapReadTxn<Uuid, AccessControlModify>,
    acps_delete: BptreeMapReadTxn<Uuid, AccessControlDelete>,
}

impl AccessControlsTransaction for AccessControlsReadTransaction {
    fn get_search(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlSearch> {
        self.acps_search.to_snapshot()
    }

    fn get_create(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlCreate> {
        self.acps_create.to_snapshot()
    }

    fn get_modify(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlModify> {
        self.acps_modify.to_snapshot()
    }

    fn get_delete(&self) -> BptreeMapReadSnapshot<Uuid, AccessControlDelete> {
        self.acps_delete.to_snapshot()
    }
}

// =========================================================================
// ACP transaction operations
// =========================================================================

impl AccessControls {
    pub fn new() -> Self {
        AccessControls {
            // inner: CowCell::new(AccessControlsInner::new()),
            acps_search: BptreeMap::new(),
            acps_create: BptreeMap::new(),
            acps_modify: BptreeMap::new(),
            acps_delete: BptreeMap::new(),
        }
    }

    pub fn read(&self) -> AccessControlsReadTransaction {
        AccessControlsReadTransaction {
            // inner: self.inner.read(),
            acps_search: self.acps_search.read(),
            acps_create: self.acps_create.read(),
            acps_modify: self.acps_modify.read(),
            acps_delete: self.acps_delete.read(),
        }
    }

    pub fn write(&self) -> AccessControlsWriteTransaction {
        AccessControlsWriteTransaction {
            // inner: self.inner.write(),
            acps_search: self.acps_search.write(),
            acps_create: self.acps_create.write(),
            acps_modify: self.acps_modify.write(),
            acps_delete: self.acps_delete.write(),
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
    use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryReduced};
    // use crate::server::QueryServerWriteTransaction;

    use crate::event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
    // use crate::filter::Filter;
    // use crate::proto_v1::Filter as ProtoFilter;
    use crate::constants::{JSON_ADMIN_V1, JSON_ANONYMOUS_V1, JSON_TESTPERSON1, JSON_TESTPERSON2};
    use crate::value::{PartialValue, Value};

    macro_rules! acp_from_entry_err {
        (
            $audit:expr,
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str($e);
            let ev1 = unsafe { e1.into_valid_committed() };

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
            let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str($e);
            let ev1 = unsafe { e1.into_valid_committed() };

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
            acw.update_search($controls).expect("Failed to update");
            let acw = acw;

            let mut audit = AuditScope::new("test_acp_search");
            let res = acw
                .search_filter_entries(&mut audit, $se, $entries)
                .expect("op failed");
            println!("result --> {:?}", res);
            println!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    #[test]
    fn test_access_internal_search() {
        // Test that an internal search bypasses ACS
        let se = unsafe { SearchEvent::new_internal_invalid(filter!(f_pres("class"))) };

        let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
                }
                }"#,
        );
        let ev1 = unsafe { e1.into_valid_committed() };

        let expect = vec![ev1.clone()];
        let entries = vec![ev1];

        // This acp basically is "allow access to stuff, but not this".
        test_acp_search!(
            &se,
            vec![unsafe {
                AccessControlSearch::from_raw(
                    "test_acp",
                    "d38640c4-0254-49f9-99b7-8ba7d0233f3d",
                    filter_valid!(f_pres("class")), // apply to all people
                    filter_valid!(f_pres("nomatchy")), // apply to none - ie no allowed results
                    "name",                         // allow to this attr, but we don't eval this.
                )
            }],
            entries,
            expect
        );
    }

    #[test]
    fn test_access_enforce_search() {
        // Test that entries from a search are reduced by acps
        let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_valid_committed() };

        let e2: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON2);
        let ev2 = unsafe { e2.into_valid_committed() };

        let r_set = vec![ev1.clone(), ev2.clone()];

        let se_admin = unsafe {
            SearchEvent::new_impersonate_entry_ser(JSON_ADMIN_V1, filter_all!(f_pres("name")))
        };
        let ex_admin = vec![ev1.clone()];

        let se_anon = unsafe {
            SearchEvent::new_impersonate_entry_ser(JSON_ANONYMOUS_V1, filter_all!(f_pres("name")))
        };
        let ex_anon = vec![];

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                "d38640c4-0254-49f9-99b7-8ba7d0233f3d",
                // apply to admin only
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                // Allow admin to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name",
            )
        };

        // Check the admin search event
        test_acp_search!(&se_admin, vec![acp.clone()], r_set.clone(), ex_admin);

        // Check the anonymous
        test_acp_search!(&se_anon, vec![acp], r_set, ex_anon);
    }

    macro_rules! test_acp_search_reduce {
        (
            $se:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::new();
            let mut acw = ac.write();
            acw.update_search($controls).expect("Failed to update");
            let acw = acw;

            let mut audit = AuditScope::new("test_acp_search_reduce");
            // We still have to reduce the entries to be sure that we are good.
            let res = acw
                .search_filter_entries(&mut audit, $se, $entries)
                .expect("operation failed");
            // Now on the reduced entries, reduce the entries attrs.
            let reduced = acw
                .search_filter_entry_attributes(&mut audit, $se, res)
                .expect("operation failed");

            // Help the type checker for the expect set.
            let expect_set: Vec<Entry<EntryReduced, EntryCommitted>> = $expect
                .into_iter()
                .map(|e| unsafe { e.into_reduced() })
                .collect();

            println!("expect --> {:?}", expect_set);
            println!("result --> {:?}", reduced);
            // should be ok, and same as expect.
            assert!(reduced == expect_set);
        }};
    }

    static JSON_TESTPERSON1_REDUCED: &'static str = r#"{
        "valid": null,
        "state": null,
        "attrs": {
            "name": ["testperson1"]
        }
    }"#;

    #[test]
    fn test_access_enforce_search_attrs() {
        // Test that attributes are correctly limited.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_valid_committed() };
        let r_set = vec![ev1.clone()];

        let ex1: Entry<EntryInvalid, EntryNew> =
            Entry::unsafe_from_entry_str(JSON_TESTPERSON1_REDUCED);
        let exv1 = unsafe { ex1.into_valid_committed() };
        let ex_anon = vec![exv1.clone()];

        let se_anon = unsafe {
            SearchEvent::new_impersonate_entry_ser(
                JSON_ANONYMOUS_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
            )
        };

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                "d38640c4-0254-49f9-99b7-8ba7d0233f3d",
                // apply to anonymous only
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("anonymous"))),
                // Allow anonymous to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name",
            )
        };

        // Finally test it!
        test_acp_search_reduce!(&se_anon, vec![acp], r_set, ex_anon);
    }

    #[test]
    fn test_access_enforce_search_attrs_req() {
        // Test that attributes are correctly limited by the request.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_valid_committed() };
        let r_set = vec![ev1.clone()];

        let ex1: Entry<EntryInvalid, EntryNew> =
            Entry::unsafe_from_entry_str(JSON_TESTPERSON1_REDUCED);
        let exv1 = unsafe { ex1.into_valid_committed() };
        let ex_anon = vec![exv1.clone()];

        let mut se_anon = unsafe {
            SearchEvent::new_impersonate_entry_ser(
                JSON_ANONYMOUS_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
            )
        };
        // the requested attrs here.
        se_anon.attrs = Some(btreeset!["name".to_string()]);

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                "d38640c4-0254-49f9-99b7-8ba7d0233f3d",
                // apply to anonymous only
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("anonymous"))),
                // Allow anonymous to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name uuid",
            )
        };

        // Finally test it!
        test_acp_search_reduce!(&se_anon, vec![acp], r_set, ex_anon);
    }

    macro_rules! test_acp_modify {
        (
            $me:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::new();
            let mut acw = ac.write();
            acw.update_modify($controls).expect("Failed to update");
            let acw = acw;

            let mut audit = AuditScope::new("test_acp_modify");
            let res = acw
                .modify_allow_operation(&mut audit, $me, $entries)
                .expect("op failed");
            println!("result --> {:?}", res);
            println!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    #[test]
    fn test_access_enforce_modify() {
        let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_valid_committed() };
        let r_set = vec![ev1.clone()];

        // Name present
        let me_pres = unsafe {
            ModifyEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                modlist!([m_pres("name", &Value::new_iutf8s("value"))]),
            )
        };
        // Name rem
        let me_rem = unsafe {
            ModifyEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                modlist!([m_remove("name", &PartialValue::new_iutf8s("value"))]),
            )
        };
        // Name purge
        let me_purge = unsafe {
            ModifyEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                modlist!([m_purge("name")]),
            )
        };

        // Class account pres
        let me_pres_class = unsafe {
            ModifyEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                modlist!([m_pres("class", &Value::new_class("account"))]),
            )
        };
        // Class account rem
        let me_rem_class = unsafe {
            ModifyEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                modlist!([m_remove("class", &PartialValue::new_class("account"))]),
            )
        };
        // Class purge
        let me_purge_class = unsafe {
            ModifyEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                modlist!([m_purge("class")]),
            )
        };

        // Allow name and class, class is account
        let acp_allow = unsafe {
            AccessControlModify::from_raw(
                "test_modify_allow",
                "87bfe9b8-7600-431e-a492-1dde64bbc455",
                // Apply to admin
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                // To modify testperson
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // Allow pres name and class
                "name class",
                // Allow rem name and class
                "name class",
                // And the class allowed is account
                "account",
            )
        };
        // Allow member, class is group. IE not account
        let acp_deny = unsafe {
            AccessControlModify::from_raw(
                "test_modify_deny",
                "87bfe9b8-7600-431e-a492-1dde64bbc456",
                // Apply to admin
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                // To modify testperson
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // Allow pres name and class
                "member class",
                // Allow rem name and class
                "member class",
                // And the class allowed is account
                "group",
            )
        };
        // Does not have a pres or rem class in attrs
        let acp_no_class = unsafe {
            AccessControlModify::from_raw(
                "test_modify_no_class",
                "87bfe9b8-7600-431e-a492-1dde64bbc457",
                // Apply to admin
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                // To modify testperson
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // Allow pres name and class
                "name class",
                // Allow rem name and class
                "name class",
                // And the class allowed is NOT an account ...
                "group",
            )
        };

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r_set, true);

        // Test rejected pres
        test_acp_modify!(&me_pres, vec![acp_deny.clone()], &r_set, false);
        // Test rejected rem
        test_acp_modify!(&me_rem, vec![acp_deny.clone()], &r_set, false);
        // Test rejected purge
        test_acp_modify!(&me_purge, vec![acp_deny.clone()], &r_set, false);

        // test allowed pres class
        test_acp_modify!(&me_pres_class, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem class
        test_acp_modify!(&me_rem_class, vec![acp_allow.clone()], &r_set, true);
        // test reject purge-class even if class present in allowed remattrs
        test_acp_modify!(&me_purge_class, vec![acp_allow.clone()], &r_set, false);

        // Test reject pres class, but class not in classes
        test_acp_modify!(&me_pres_class, vec![acp_no_class.clone()], &r_set, false);
        // Test reject pres class, class in classes but not in pres attrs
        test_acp_modify!(&me_pres_class, vec![acp_deny.clone()], &r_set, false);
        // test reject rem class, but class not in classes
        test_acp_modify!(&me_rem_class, vec![acp_no_class.clone()], &r_set, false);
        // test reject rem class, class in classes but not in pres attrs
        test_acp_modify!(&me_rem_class, vec![acp_deny.clone()], &r_set, false);
    }

    macro_rules! test_acp_create {
        (
            $ce:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::new();
            let mut acw = ac.write();
            acw.update_create($controls).expect("Failed to update");
            let acw = acw;

            let mut audit = AuditScope::new("test_acp_create");
            let res = acw
                .create_allow_operation(&mut audit, $ce, $entries)
                .expect("op failed");
            println!("result --> {:?}", res);
            println!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    static JSON_TEST_CREATE_AC1: &'static str = r#"{
        "valid": null,
        "state": null,
        "attrs": {
            "class": ["account"],
            "name": ["testperson1"],
            "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
        }
    }"#;

    static JSON_TEST_CREATE_AC2: &'static str = r#"{
        "valid": null,
        "state": null,
        "attrs": {
            "class": ["account"],
            "name": ["testperson1"],
            "notallowed": ["not allowed!"],
            "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
        }
    }"#;

    static JSON_TEST_CREATE_AC3: &'static str = r#"{
        "valid": null,
        "state": null,
        "attrs": {
            "class": ["account", "notallowed"],
            "name": ["testperson1"],
            "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
        }
    }"#;

    static JSON_TEST_CREATE_AC4: &'static str = r#"{
        "valid": null,
        "state": null,
        "attrs": {
            "class": ["account", "group"],
            "name": ["testperson1"],
            "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
        }
    }"#;

    #[test]
    fn test_access_enforce_create() {
        let ev1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TEST_CREATE_AC1);
        let r1_set = vec![ev1.clone()];

        let ev2: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TEST_CREATE_AC2);
        let r2_set = vec![ev2.clone()];

        let ev3: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TEST_CREATE_AC3);
        let r3_set = vec![ev3.clone()];

        let ev4: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TEST_CREATE_AC4);
        let r4_set = vec![ev4.clone()];

        // In this case, we can make the create event with an empty entry
        // set because we only reference the entries in r_set in the test.
        //
        // In the realy server code, the entry set is derived from and checked
        // against the create event, so we have some level of trust in it.
        let ce_admin = unsafe { CreateEvent::new_impersonate_entry_ser(JSON_ADMIN_V1, vec![]) };

        let acp = unsafe {
            AccessControlCreate::from_raw(
                "test_create",
                "87bfe9b8-7600-431e-a492-1dde64bbc453",
                // Apply to admin
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                // To create matching filter testperson
                // Can this be empty?
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // classes
                "account",
                // attrs
                "class name uuid",
            )
        };

        let acp2 = unsafe {
            AccessControlCreate::from_raw(
                "test_create_2",
                "87bfe9b8-7600-431e-a492-1dde64bbc454",
                // Apply to admin
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                // To create matching filter testperson
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
                // classes
                "group",
                // attrs
                "class name uuid",
            )
        };

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test reject create (not allowed attr)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r2_set, false);
        // Test reject create (not allowed class)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r3_set, false);
        // Test reject create (hybrid u + g entry w_ u & g create allow)
        test_acp_create!(&ce_admin, vec![acp, acp2], &r4_set, false);
    }

    macro_rules! test_acp_delete {
        (
            $de:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::new();
            let mut acw = ac.write();
            acw.update_delete($controls).expect("Failed to update");
            let acw = acw;

            let mut audit = AuditScope::new("test_acp_delete");
            let res = acw
                .delete_allow_operation(&mut audit, $de, $entries)
                .expect("op failed");
            println!("result --> {:?}", res);
            println!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    #[test]
    fn test_access_enforce_delete() {
        let e1: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_valid_committed() };
        let r_set = vec![ev1.clone()];

        let de_admin = unsafe {
            DeleteEvent::new_impersonate_entry_ser(
                JSON_ADMIN_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
            )
        };

        let de_anon = unsafe {
            DeleteEvent::new_impersonate_entry_ser(
                JSON_ANONYMOUS_V1,
                filter_all!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
            )
        };

        let acp = unsafe {
            AccessControlDelete::from_raw(
                "test_delete",
                "87bfe9b8-7600-431e-a492-1dde64bbc453",
                // Apply to admin
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("admin"))),
                // To delete testperson
                filter_valid!(f_eq("name", PartialValue::new_iutf8s("testperson1"))),
            )
        };

        // Test allowed to delete
        test_acp_delete!(&de_admin, vec![acp.clone()], &r_set, true);
        // Test reject delete
        test_acp_delete!(&de_anon, vec![acp], &r_set, false);
    }
}
