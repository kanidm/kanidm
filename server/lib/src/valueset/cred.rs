use smolset::SmolSet;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;
use time::OffsetDateTime;

use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey as AttestedPasskeyV4, Passkey as PasskeyV4,
};

use crate::be::dbvalue::{
    DbValueAttestedPasskeyV1, DbValueCredV1, DbValueIntentTokenStateV1, DbValuePasskeyV1,
};
use crate::credential::Credential;
use crate::prelude::*;
use crate::repl::proto::{
    ReplAttestedPasskeyV4V1, ReplAttrV1, ReplCredV1, ReplIntentTokenV1, ReplPasskeyV4V1,
};
use crate::schema::SchemaAttribute;
use crate::utils::trigraph_iter;
use crate::value::{CredUpdateSessionPerms, CredentialType, IntentTokenState};
use crate::valueset::{DbValueSetV2, ValueSet};

use kanidm_proto::scim_v1::server::{ScimIntentToken, ScimIntentTokenState};

#[derive(Debug, Clone)]
pub struct ValueSetCredential {
    map: BTreeMap<String, Credential>,
}

impl ValueSetCredential {
    pub fn new(t: String, c: Credential) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, c);
        Box::new(ValueSetCredential { map })
    }

    pub fn push(&mut self, t: String, c: Credential) -> bool {
        self.map.insert(t, c).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueCredV1>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|dc| {
                let t = dc.tag.clone();
                Credential::try_from(dc.data)
                    .map_err(|()| OperationError::InvalidValueState)
                    .map(|c| (t, c))
            })
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetCredential { map }))
    }

    pub fn from_repl_v1(data: &[ReplCredV1]) -> Result<ValueSet, OperationError> {
        let map = data
            .iter()
            .map(Credential::try_from_repl_v1)
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetCredential { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, Credential)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetCredential { map }))
    }
}

impl ValueSetT for ValueSetCredential {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Cred(t, c) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(t) {
                    e.insert(c);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Cred(t) => self.map.remove(t.as_str()).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Cred(t) => self.map.contains_key(t.as_str()),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    fn generate_idx_sub_keys(&self) -> Vec<String> {
        let lower: Vec<_> = self.map.keys().map(|s| s.to_lowercase()).collect();
        let mut trigraphs: Vec<_> = lower.iter().flat_map(|v| trigraph_iter(v)).collect();

        trigraphs.sort_unstable();
        trigraphs.dedup();

        trigraphs.into_iter().map(String::from).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Credential
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .iter()
            .all(|(s, _)| Value::validate_str_escapes(s) && Value::validate_singleline(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.keys().cloned())
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        // Currently I think we don't need to yield cred info as that's part of the
        // cred update session instead.
        None
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Credential(
            self.map
                .iter()
                .map(|(tag, cred)| DbValueCredV1 {
                    tag: tag.clone(),
                    data: cred.to_db_valuev1(),
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Credential {
            set: self
                .map
                .iter()
                .map(|(tag, cred)| cred.to_repl_v1(tag.clone()))
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Cred))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(t, c)| Value::Cred(t.clone(), c.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        // Looks like we may not need this?
        if let Some(other) = other.as_credential_map() {
            &self.map == other
        } else {
            // debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_credential_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_credential_single(&self) -> Option<&Credential> {
        if self.map.len() == 1 {
            self.map.values().take(1).next()
        } else {
            None
        }
    }

    fn as_credential_map(&self) -> Option<&BTreeMap<String, Credential>> {
        Some(&self.map)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetIntentToken {
    map: BTreeMap<String, IntentTokenState>,
}

impl ValueSetIntentToken {
    pub fn new(t: String, s: IntentTokenState) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, s);
        Box::new(ValueSetIntentToken { map })
    }

    pub fn push(&mut self, t: String, s: IntentTokenState) -> bool {
        self.map.insert(t, s).is_none()
    }

    pub fn from_dbvs2(
        data: Vec<(String, DbValueIntentTokenStateV1)>,
    ) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|(s, dits)| {
                let ts = match dits {
                    DbValueIntentTokenStateV1::Valid {
                        max_ttl,
                        ext_cred_portal_can_view,
                        primary_can_edit,
                        passkeys_can_edit,
                        attested_passkeys_can_edit,
                        unixcred_can_edit,
                        sshpubkey_can_edit,
                    } => IntentTokenState::Valid {
                        max_ttl,
                        perms: CredUpdateSessionPerms {
                            ext_cred_portal_can_view,
                            primary_can_edit,
                            passkeys_can_edit,
                            attested_passkeys_can_edit,
                            unixcred_can_edit,
                            sshpubkey_can_edit,
                        },
                    },
                    DbValueIntentTokenStateV1::InProgress {
                        max_ttl,
                        session_id,
                        session_ttl,
                        ext_cred_portal_can_view,
                        primary_can_edit,
                        passkeys_can_edit,
                        attested_passkeys_can_edit,
                        unixcred_can_edit,
                        sshpubkey_can_edit,
                    } => IntentTokenState::InProgress {
                        max_ttl,
                        session_id,
                        session_ttl,
                        perms: CredUpdateSessionPerms {
                            ext_cred_portal_can_view,
                            primary_can_edit,
                            passkeys_can_edit,
                            attested_passkeys_can_edit,
                            unixcred_can_edit,
                            sshpubkey_can_edit,
                        },
                    },
                    DbValueIntentTokenStateV1::Consumed { max_ttl } => {
                        IntentTokenState::Consumed { max_ttl }
                    }
                };
                (s, ts)
            })
            .collect();
        Ok(Box::new(ValueSetIntentToken { map }))
    }

    pub fn from_repl_v1(data: &[ReplIntentTokenV1]) -> Result<ValueSet, OperationError> {
        let map = data
            .iter()
            .map(|dits| match dits {
                ReplIntentTokenV1::Valid {
                    token_id,
                    max_ttl,
                    ext_cred_portal_can_view,
                    primary_can_edit,
                    passkeys_can_edit,
                    attested_passkeys_can_edit,
                    unixcred_can_edit,
                    sshpubkey_can_edit,
                } => (
                    token_id.clone(),
                    IntentTokenState::Valid {
                        max_ttl: *max_ttl,
                        perms: CredUpdateSessionPerms {
                            ext_cred_portal_can_view: *ext_cred_portal_can_view,
                            primary_can_edit: *primary_can_edit,
                            passkeys_can_edit: *passkeys_can_edit,
                            attested_passkeys_can_edit: *attested_passkeys_can_edit,
                            unixcred_can_edit: *unixcred_can_edit,
                            sshpubkey_can_edit: *sshpubkey_can_edit,
                        },
                    },
                ),
                ReplIntentTokenV1::InProgress {
                    token_id,
                    max_ttl,
                    session_id,
                    session_ttl,
                    ext_cred_portal_can_view,
                    primary_can_edit,
                    passkeys_can_edit,
                    attested_passkeys_can_edit,
                    unixcred_can_edit,
                    sshpubkey_can_edit,
                } => (
                    token_id.clone(),
                    IntentTokenState::InProgress {
                        max_ttl: *max_ttl,
                        session_id: *session_id,
                        session_ttl: *session_ttl,
                        perms: CredUpdateSessionPerms {
                            ext_cred_portal_can_view: *ext_cred_portal_can_view,
                            primary_can_edit: *primary_can_edit,
                            passkeys_can_edit: *passkeys_can_edit,
                            attested_passkeys_can_edit: *attested_passkeys_can_edit,
                            unixcred_can_edit: *unixcred_can_edit,
                            sshpubkey_can_edit: *sshpubkey_can_edit,
                        },
                    },
                ),
                ReplIntentTokenV1::Consumed { token_id, max_ttl } => (
                    token_id.clone(),
                    IntentTokenState::Consumed { max_ttl: *max_ttl },
                ),
            })
            .collect();
        Ok(Box::new(ValueSetIntentToken { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, IntentTokenState)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetIntentToken { map }))
    }
}

impl ValueSetT for ValueSetIntentToken {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::IntentToken(u, s) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert(s);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::IntentToken(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn purge(&mut self, _cid: &Cid) -> bool {
        // Could consider making this a TS capable entry.
        true
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::IntentToken(u) => self.map.contains_key(u),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::IntentToken
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .iter()
            .all(|(s, _)| Value::validate_str_escapes(s) && Value::validate_singleline(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.keys().cloned())
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        Some(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(token_id, intent_token_state)| {
                    let (state, max_ttl) = match intent_token_state {
                        IntentTokenState::Valid { max_ttl, .. } => {
                            (ScimIntentTokenState::Valid, *max_ttl)
                        }
                        IntentTokenState::InProgress { max_ttl, .. } => {
                            (ScimIntentTokenState::InProgress, *max_ttl)
                        }
                        IntentTokenState::Consumed { max_ttl } => {
                            (ScimIntentTokenState::Consumed, *max_ttl)
                        }
                    };

                    let odt: OffsetDateTime = OffsetDateTime::UNIX_EPOCH + max_ttl;

                    ScimIntentToken {
                        token_id: token_id.clone(),
                        state,
                        expires: odt,
                    }
                })
                .collect::<Vec<_>>(),
        ))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::IntentToken(
            self.map
                .iter()
                .map(|(u, s)| {
                    (
                        u.clone(),
                        match s {
                            IntentTokenState::Valid {
                                max_ttl,
                                perms:
                                    CredUpdateSessionPerms {
                                        ext_cred_portal_can_view,
                                        primary_can_edit,
                                        passkeys_can_edit,
                                        attested_passkeys_can_edit,
                                        unixcred_can_edit,
                                        sshpubkey_can_edit,
                                    },
                            } => DbValueIntentTokenStateV1::Valid {
                                max_ttl: *max_ttl,
                                ext_cred_portal_can_view: *ext_cred_portal_can_view,
                                primary_can_edit: *primary_can_edit,
                                passkeys_can_edit: *passkeys_can_edit,
                                attested_passkeys_can_edit: *attested_passkeys_can_edit,
                                unixcred_can_edit: *unixcred_can_edit,
                                sshpubkey_can_edit: *sshpubkey_can_edit,
                            },
                            IntentTokenState::InProgress {
                                max_ttl,
                                session_id,
                                session_ttl,
                                perms:
                                    CredUpdateSessionPerms {
                                        ext_cred_portal_can_view,
                                        primary_can_edit,
                                        passkeys_can_edit,
                                        attested_passkeys_can_edit,
                                        unixcred_can_edit,
                                        sshpubkey_can_edit,
                                    },
                            } => DbValueIntentTokenStateV1::InProgress {
                                max_ttl: *max_ttl,
                                session_id: *session_id,
                                session_ttl: *session_ttl,
                                ext_cred_portal_can_view: *ext_cred_portal_can_view,
                                primary_can_edit: *primary_can_edit,
                                passkeys_can_edit: *passkeys_can_edit,
                                attested_passkeys_can_edit: *attested_passkeys_can_edit,
                                unixcred_can_edit: *unixcred_can_edit,
                                sshpubkey_can_edit: *sshpubkey_can_edit,
                            },
                            IntentTokenState::Consumed { max_ttl } => {
                                DbValueIntentTokenStateV1::Consumed { max_ttl: *max_ttl }
                            }
                        },
                    )
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::IntentToken {
            set: self
                .map
                .iter()
                .map(|(u, s)| match s {
                    IntentTokenState::Valid {
                        max_ttl,
                        perms:
                            CredUpdateSessionPerms {
                                ext_cred_portal_can_view,
                                primary_can_edit,
                                passkeys_can_edit,
                                attested_passkeys_can_edit,
                                unixcred_can_edit,
                                sshpubkey_can_edit,
                            },
                    } => ReplIntentTokenV1::Valid {
                        token_id: u.clone(),
                        max_ttl: *max_ttl,
                        ext_cred_portal_can_view: *ext_cred_portal_can_view,
                        primary_can_edit: *primary_can_edit,
                        passkeys_can_edit: *passkeys_can_edit,
                        attested_passkeys_can_edit: *attested_passkeys_can_edit,
                        unixcred_can_edit: *unixcred_can_edit,
                        sshpubkey_can_edit: *sshpubkey_can_edit,
                    },
                    IntentTokenState::InProgress {
                        max_ttl,
                        session_id,
                        session_ttl,
                        perms:
                            CredUpdateSessionPerms {
                                ext_cred_portal_can_view,
                                primary_can_edit,
                                passkeys_can_edit,
                                attested_passkeys_can_edit,
                                unixcred_can_edit,
                                sshpubkey_can_edit,
                            },
                    } => ReplIntentTokenV1::InProgress {
                        token_id: u.clone(),
                        max_ttl: *max_ttl,
                        session_id: *session_id,
                        session_ttl: *session_ttl,
                        ext_cred_portal_can_view: *ext_cred_portal_can_view,
                        primary_can_edit: *primary_can_edit,
                        passkeys_can_edit: *passkeys_can_edit,
                        attested_passkeys_can_edit: *attested_passkeys_can_edit,
                        unixcred_can_edit: *unixcred_can_edit,
                        sshpubkey_can_edit: *sshpubkey_can_edit,
                    },
                    IntentTokenState::Consumed { max_ttl } => ReplIntentTokenV1::Consumed {
                        token_id: u.clone(),
                        max_ttl: *max_ttl,
                    },
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::IntentToken))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, s)| Value::IntentToken(u.clone(), s.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_intenttoken_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_intenttoken_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn repl_merge_valueset(&self, _older: &ValueSet, _trim_cid: &Cid) -> Option<ValueSet> {
        // Im not sure this actually needs repl handling ...
        None
    }

    fn as_intenttoken_map(&self) -> Option<&BTreeMap<String, IntentTokenState>> {
        Some(&self.map)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetPasskey {
    map: BTreeMap<Uuid, (String, PasskeyV4)>,
}

impl ValueSetPasskey {
    pub fn new(u: Uuid, t: String, k: PasskeyV4) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(u, (t, k));
        Box::new(ValueSetPasskey { map })
    }

    pub fn push(&mut self, u: Uuid, t: String, k: PasskeyV4) -> bool {
        self.map.insert(u, (t, k)).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValuePasskeyV1>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|k| match k {
                DbValuePasskeyV1::V4 { u, t, k } => Ok((u, (t, k))),
            })
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetPasskey { map }))
    }

    pub fn from_repl_v1(data: &[ReplPasskeyV4V1]) -> Result<ValueSet, OperationError> {
        let map = data
            .iter()
            .cloned()
            .map(|ReplPasskeyV4V1 { uuid, tag, key }| Ok((uuid, (tag, key))))
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetPasskey { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, String, PasskeyV4)>,
    {
        let map = iter.into_iter().map(|(u, t, k)| (u, (t, k))).collect();
        Some(Box::new(ValueSetPasskey { map }))
    }
}

impl ValueSetT for ValueSetPasskey {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Passkey(u, t, k) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert((t, k));
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Passkey(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Passkey(u) => self.map.contains_key(u),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map
            .keys()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Passkey
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .iter()
            .all(|(_, (s, _))| Value::validate_str_escapes(s) && Value::validate_singleline(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.values().map(|(t, _)| t).cloned())
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        None
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Passkey(
            self.map
                .iter()
                .map(|(u, (t, k))| DbValuePasskeyV1::V4 {
                    u: *u,
                    t: t.clone(),
                    k: k.clone(),
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Passkey {
            set: self
                .map
                .iter()
                .map(|(u, (t, k))| ReplPasskeyV4V1 {
                    uuid: *u,
                    tag: t.clone(),
                    key: k.clone(),
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Passkey))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, (t, k))| Value::Passkey(*u, t.clone(), k.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        // Looks like we may not need this?
        if let Some(other) = other.as_passkey_map() {
            &self.map == other
        } else {
            // debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_passkey_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_passkey_single(&self) -> Option<&PasskeyV4> {
        if self.map.len() == 1 {
            self.map.values().take(1).next().map(|(_, k)| k)
        } else {
            None
        }
    }

    fn as_passkey_map(&self) -> Option<&BTreeMap<Uuid, (String, PasskeyV4)>> {
        Some(&self.map)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetAttestedPasskey {
    map: BTreeMap<Uuid, (String, AttestedPasskeyV4)>,
}

impl ValueSetAttestedPasskey {
    pub fn new(u: Uuid, t: String, k: AttestedPasskeyV4) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(u, (t, k));
        Box::new(ValueSetAttestedPasskey { map })
    }

    pub fn push(&mut self, u: Uuid, t: String, k: AttestedPasskeyV4) -> bool {
        self.map.insert(u, (t, k)).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueAttestedPasskeyV1>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .map(|k| match k {
                DbValueAttestedPasskeyV1::V4 { u, t, k } => Ok((u, (t, k))),
            })
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetAttestedPasskey { map }))
    }

    pub fn from_repl_v1(data: &[ReplAttestedPasskeyV4V1]) -> Result<ValueSet, OperationError> {
        let map = data
            .iter()
            .cloned()
            .map(|ReplAttestedPasskeyV4V1 { uuid, tag, key }| Ok((uuid, (tag, key))))
            .collect::<Result<_, _>>()?;
        Ok(Box::new(ValueSetAttestedPasskey { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, String, AttestedPasskeyV4)>,
    {
        let map = iter.into_iter().map(|(u, t, k)| (u, (t, k))).collect();
        Some(Box::new(ValueSetAttestedPasskey { map }))
    }
}

impl ValueSetT for ValueSetAttestedPasskey {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::AttestedPasskey(u, t, k) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert((t, k));
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::AttestedPasskey(u) => self.map.remove(u).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::AttestedPasskey(u) => self.map.contains_key(u),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map
            .keys()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::AttestedPasskey
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .iter()
            .all(|(_, (s, _))| Value::validate_str_escapes(s) && Value::validate_singleline(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.values().map(|(t, _)| t).cloned())
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        None
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::AttestedPasskey(
            self.map
                .iter()
                .map(|(u, (t, k))| DbValueAttestedPasskeyV1::V4 {
                    u: *u,
                    t: t.clone(),
                    k: k.clone(),
                })
                .collect(),
        )
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::AttestedPasskey {
            set: self
                .map
                .iter()
                .map(|(u, (t, k))| ReplAttestedPasskeyV4V1 {
                    uuid: *u,
                    tag: t.clone(),
                    key: k.clone(),
                })
                .collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().copied().map(PartialValue::AttestedPasskey))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, (t, k))| Value::AttestedPasskey(*u, t.clone(), k.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        // Looks like we may not need this?
        if let Some(other) = other.as_attestedpasskey_map() {
            &self.map == other
        } else {
            // debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_attestedpasskey_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    /*
    fn to_attestedpasskey_single(&self) -> Option<&AttestedPasskeyV4> {
        if self.map.len() == 1 {
            self.map.values().take(1).next().map(|(_, k)| k)
        } else {
            None
        }
    }
    */

    fn as_attestedpasskey_map(&self) -> Option<&BTreeMap<Uuid, (String, AttestedPasskeyV4)>> {
        Some(&self.map)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetCredentialType {
    set: SmolSet<[CredentialType; 1]>,
}

impl ValueSetCredentialType {
    pub fn new(u: CredentialType) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(u);
        Box::new(ValueSetCredentialType { set })
    }

    pub fn push(&mut self, u: CredentialType) -> bool {
        self.set.insert(u)
    }

    pub fn from_dbvs2(data: Vec<u16>) -> Result<ValueSet, OperationError> {
        let set: Result<_, _> = data.into_iter().map(CredentialType::try_from).collect();
        let set = set.map_err(|_| OperationError::InvalidValueState)?;
        Ok(Box::new(ValueSetCredentialType { set }))
    }

    pub fn from_repl_v1(data: &[u16]) -> Result<ValueSet, OperationError> {
        let set: Result<_, _> = data.iter().copied().map(CredentialType::try_from).collect();
        let set = set.map_err(|_| OperationError::InvalidValueState)?;
        Ok(Box::new(ValueSetCredentialType { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and uuid is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = CredentialType>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetCredentialType { set }))
    }
}

impl ValueSetT for ValueSetCredentialType {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::CredentialType(u) => Ok(self.set.insert(u)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::CredentialType(u) => self.set.remove(u),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::CredentialType(u) => self.set.contains(u),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().map(|u| u.to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::CredentialType
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|ct| ct.to_string()))
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        Some(ScimValueKanidm::from(
            self.set.iter().map(|ct| ct.to_string()).collect::<Vec<_>>(),
        ))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::CredentialType(self.set.iter().map(|s| *s as u16).collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::CredentialType {
            set: self.set.iter().map(|s| *s as u16).collect(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().copied().map(PartialValue::CredentialType))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().copied().map(Value::CredentialType))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_credentialtype_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_credentialtype_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_credentialtype_single(&self) -> Option<CredentialType> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }

    fn as_credentialtype_set(&self) -> Option<&SmolSet<[CredentialType; 1]>> {
        Some(&self.set)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetWebauthnAttestationCaList {
    ca_list: AttestationCaList,
}

impl ValueSetWebauthnAttestationCaList {
    pub fn new(ca_list: AttestationCaList) -> Box<Self> {
        Box::new(ValueSetWebauthnAttestationCaList { ca_list })
    }

    /*
    pub fn push(&mut self, u: CredentialType) -> bool {
        self.set.insert(u)
    }
    */

    pub fn from_dbvs2(ca_list: AttestationCaList) -> Result<ValueSet, OperationError> {
        Ok(Box::new(ValueSetWebauthnAttestationCaList { ca_list }))
    }

    pub fn from_repl_v1(ca_list: &AttestationCaList) -> Result<ValueSet, OperationError> {
        Ok(Box::new(ValueSetWebauthnAttestationCaList {
            ca_list: ca_list.clone(),
        }))
    }

    /*
    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and uuid is foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = CredentialType>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetCredentialType { set }))
    }
    */
}

impl ValueSetT for ValueSetWebauthnAttestationCaList {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::WebauthnAttestationCaList(u) => {
                self.ca_list.union(&u);
                Ok(true)
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.ca_list.clear();
    }

    fn remove(&mut self, _pv: &PartialValue, _cid: &Cid) -> bool {
        /*
        match pv {
            _ => {
                debug_assert!(false);
                true
            }
        }
        */
        debug_assert!(false);
        true
    }

    fn contains(&self, _pv: &PartialValue) -> bool {
        /*
        match pv {
            PartialValue::CredentialType(u) => self.set.contains(u),
            _ => false,
        }
        */
        false
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.ca_list.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        // self.set.iter().map(|u| u.to_string()).collect()
        Vec::with_capacity(0)
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::WebauthnAttestationCaList
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        // Should we actually be looking through the ca-list as given and eliminate
        // known vuln devices?
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.ca_list
                .cas()
                .values()
                .flat_map(|att_ca| att_ca.aaguids().values())
                .map(|device| device.description_en().to_string()),
        )
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::WebauthnAttestationCaList {
            ca_list: self.ca_list.clone(),
        }
    }

    fn to_scim_value(&self) -> Option<ScimValueKanidm> {
        Some(ScimValueKanidm::from(
            self.ca_list
                .cas()
                .values()
                .flat_map(|att_ca| att_ca.aaguids().values())
                .map(|device| device.description_en().to_string())
                .collect::<Vec<_>>(),
        ))
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::WebauthnAttestationCaList {
            ca_list: self.ca_list.clone(),
        }
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(std::iter::empty::<PartialValue>())
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(std::iter::once(Value::WebauthnAttestationCaList(
            self.ca_list.clone(),
        )))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_webauthn_attestation_ca_list() {
            &self.ca_list == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_webauthn_attestation_ca_list() {
            self.ca_list.union(b);
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_webauthn_attestation_ca_list(&self) -> Option<&AttestationCaList> {
        Some(&self.ca_list)
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialType, IntentTokenState, ValueSetCredentialType, ValueSetIntentToken};
    use crate::prelude::ValueSet;
    use std::time::Duration;

    #[test]
    fn test_scim_intent_token() {
        // I seem to recall this shouldn't have a value returned?
        let vs: ValueSet = ValueSetIntentToken::new(
            "ca6f29d1-034b-41fb-abc1-4bb9f0548e67".to_string(),
            IntentTokenState::Consumed {
                max_ttl: Duration::from_secs(300),
            },
        );

        let data = r#"
[
  {
    "expires": "1970-01-01T00:05:00Z",
    "state": "consumed",
    "tokenId": "ca6f29d1-034b-41fb-abc1-4bb9f0548e67"
  }
]
        "#;
        crate::valueset::scim_json_reflexive(vs, data);
    }

    #[test]
    fn test_scim_credential_type() {
        let vs: ValueSet = ValueSetCredentialType::new(CredentialType::Mfa);
        crate::valueset::scim_json_reflexive(vs, r#"["mfa"]"#);
    }
}
