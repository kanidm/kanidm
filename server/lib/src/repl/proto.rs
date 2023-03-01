use super::cid::Cid;
use super::entry::EntryChangeState;
use super::entry::State;
use crate::entry::Eattrs;
use crate::prelude::*;
use crate::schema::{SchemaReadTransaction, SchemaTransaction};
use crate::valueset;
use base64urlsafedata::Base64UrlSafeData;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use webauthn_rs::prelude::{
    DeviceKey as DeviceKeyV4, Passkey as PasskeyV4, SecurityKey as SecurityKeyV4,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplCidV1 {
    #[serde(rename = "t")]
    pub ts: Duration,
    #[serde(rename = "s")]
    pub s_uuid: Uuid,
}

// From / Into CID
impl From<&Cid> for ReplCidV1 {
    fn from(cid: &Cid) -> Self {
        ReplCidV1 {
            ts: cid.ts,
            s_uuid: cid.s_uuid,
        }
    }
}

impl From<ReplCidV1> for Cid {
    fn from(cid: ReplCidV1) -> Self {
        Cid {
            ts: cid.ts,
            s_uuid: cid.s_uuid,
        }
    }
}

impl From<&ReplCidV1> for Cid {
    fn from(cid: &ReplCidV1) -> Self {
        Cid {
            ts: cid.ts,
            s_uuid: cid.s_uuid,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ReplAddressV1 {
    #[serde(rename = "f")]
    pub formatted: String,
    #[serde(rename = "s")]
    pub street_address: String,
    #[serde(rename = "l")]
    pub locality: String,
    #[serde(rename = "r")]
    pub region: String,
    #[serde(rename = "p")]
    pub postal_code: String,
    #[serde(rename = "c")]
    pub country: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplTotpAlgoV1 {
    S1,
    S256,
    S512,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplTotpV1 {
    pub key: Base64UrlSafeData,
    pub step: u64,
    pub algo: ReplTotpAlgoV1,
    pub digits: u8,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ReplPasswordV1 {
    PBKDF2 {
        cost: usize,
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    PBKDF2_SHA1 {
        cost: usize,
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    PBKDF2_SHA512 {
        cost: usize,
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    SSHA512 {
        salt: Base64UrlSafeData,
        hash: Base64UrlSafeData,
    },
    NT_MD4 {
        hash: Base64UrlSafeData,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplBackupCodeV1 {
    pub codes: BTreeSet<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplCredV1 {
    TmpWn {
        tag: String,
        set: Vec<ReplPasskeyV4V1>,
    },
    Password {
        tag: String,
        password: ReplPasswordV1,
        uuid: Uuid,
    },
    GenPassword {
        tag: String,
        password: ReplPasswordV1,
        uuid: Uuid,
    },
    PasswordMfa {
        tag: String,
        password: ReplPasswordV1,
        totp: Vec<(String, ReplTotpV1)>,
        backup_code: Option<ReplBackupCodeV1>,
        webauthn: Vec<ReplSecurityKeyV4V1>,
        uuid: Uuid,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplIntentTokenV1 {
    Valid {
        token_id: String,
        max_ttl: Duration,
    },
    InProgress {
        token_id: String,
        max_ttl: Duration,
        session_id: Uuid,
        session_ttl: Duration,
    },
    Consumed {
        token_id: String,
        max_ttl: Duration,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReplSecurityKeyV4V1 {
    pub tag: String,
    pub key: SecurityKeyV4,
}

impl Eq for ReplSecurityKeyV4V1 {}

impl PartialEq for ReplSecurityKeyV4V1 {
    fn eq(&self, other: &Self) -> bool {
        self.key.cred_id() == other.key.cred_id()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReplPasskeyV4V1 {
    pub uuid: Uuid,
    pub tag: String,
    pub key: PasskeyV4,
}

impl Eq for ReplPasskeyV4V1 {}

impl PartialEq for ReplPasskeyV4V1 {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid && self.key.cred_id() == other.key.cred_id()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReplDeviceKeyV4V1 {
    pub uuid: Uuid,
    pub tag: String,
    pub key: DeviceKeyV4,
}

impl Eq for ReplDeviceKeyV4V1 {}

impl PartialEq for ReplDeviceKeyV4V1 {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid && self.key.cred_id() == other.key.cred_id()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplOauthScopeMapV1 {
    pub refer: Uuid,
    pub data: BTreeSet<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplOauth2SessionV1 {
    pub refer: Uuid,
    pub parent: Uuid,
    pub expiry: Option<String>,
    pub issued_at: String,
    pub rs_uuid: Uuid,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub enum ReplSessionScopeV1 {
    #[default]
    ReadOnly,
    ReadWrite,
    PrivilegeCapable,
    Synchronise,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub enum ReplApiTokenScopeV1 {
    #[default]
    ReadOnly,
    ReadWrite,
    Synchronise,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplIdentityIdV1 {
    Internal,
    Uuid(Uuid),
    Synch(Uuid),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplSessionV1 {
    pub refer: Uuid,
    pub label: String,
    pub expiry: Option<String>,
    pub issued_at: String,
    pub issued_by: ReplIdentityIdV1,
    pub cred_id: Uuid,
    pub scope: ReplSessionScopeV1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplApiTokenV1 {
    pub refer: Uuid,
    pub label: String,
    pub expiry: Option<String>,
    pub issued_at: String,
    pub issued_by: ReplIdentityIdV1,
    pub scope: ReplApiTokenScopeV1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplAttrV1 {
    Address {
        set: Vec<ReplAddressV1>,
    },
    EmailAddress {
        primary: String,
        set: Vec<String>,
    },
    PublicBinary {
        set: Vec<(String, Base64UrlSafeData)>,
    },
    PrivateBinary {
        set: Vec<Base64UrlSafeData>,
    },
    Bool {
        set: Vec<bool>,
    },
    Cid {
        set: Vec<ReplCidV1>,
    },
    Credential {
        set: Vec<ReplCredV1>,
    },
    IntentToken {
        set: Vec<ReplIntentTokenV1>,
    },
    Passkey {
        set: Vec<ReplPasskeyV4V1>,
    },
    DeviceKey {
        set: Vec<ReplDeviceKeyV4V1>,
    },
    DateTime {
        set: Vec<String>,
    },
    Iname {
        set: Vec<String>,
    },
    IndexType {
        set: Vec<u16>,
    },
    Iutf8 {
        set: Vec<String>,
    },
    JsonFilter {
        set: Vec<String>,
    },
    JwsKeyEs256 {
        set: Vec<Base64UrlSafeData>,
    },
    JwsKeyRs256 {
        set: Vec<Base64UrlSafeData>,
    },
    NsUniqueId {
        set: Vec<String>,
    },
    SecretValue {
        set: Vec<String>,
    },
    RestrictedString {
        set: Vec<String>,
    },
    Uint32 {
        set: Vec<u32>,
    },
    Url {
        set: Vec<Url>,
    },
    Utf8 {
        set: Vec<String>,
    },
    Uuid {
        set: Vec<Uuid>,
    },
    Reference {
        set: Vec<Uuid>,
    },
    SyntaxType {
        set: Vec<u16>,
    },
    Spn {
        set: Vec<(String, String)>,
    },
    UiHint {
        set: Vec<u16>,
    },
    SshKey {
        set: Vec<(String, String)>,
    },
    OauthScope {
        set: Vec<String>,
    },
    OauthScopeMap {
        set: Vec<ReplOauthScopeMapV1>,
    },
    Oauth2Session {
        set: Vec<ReplOauth2SessionV1>,
    },
    Session {
        set: Vec<ReplSessionV1>,
    },
    ApiToken {
        set: Vec<ReplApiTokenV1>,
    },
    TotpSecret {
        set: Vec<(String, ReplTotpV1)>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplAttrStateV1 {
    cid: ReplCidV1,
    attr: Option<ReplAttrV1>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplStateV1 {
    Live {
        attrs: BTreeMap<String, ReplAttrStateV1>,
    },
    Tombstone {
        at: ReplCidV1,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
// I think partial entries should be separate? This clearly implies a refresh.
pub struct ReplEntryV1 {
    uuid: Uuid,
    // Change State
    st: ReplStateV1,
}

impl ReplEntryV1 {
    pub fn new(entry: &EntrySealedCommitted, schema: &SchemaReadTransaction) -> ReplEntryV1 {
        let cs = entry.get_changestate();
        let uuid = entry.get_uuid();

        let st = match cs.current() {
            State::Live { changes } => {
                let live_attrs = entry.get_ava();

                let attrs = changes
                    .iter()
                    .filter_map(|(attr_name, cid)| {
                        if schema.is_replicated(attr_name) {
                            let live_attr = live_attrs.get(attr_name.as_str());

                            let cid = cid.into();
                            let attr = live_attr.and_then(|maybe|
                                // There is a quirk in the way we currently handle certain
                                // types of adds/deletes that it may be possible to have an
                                // empty value set still in memory on a supplier. In the future
                                // we may make it so in memory valuesets can be empty and sent
                                // but for now, if it's an empty set in any capacity, we map
                                // to None and just send the Cid since they have the same result
                                // on how the entry/attr state looks at each end.
                                if maybe.len() > 0 {
                                    Some(maybe.to_repl_v1())
                                } else {
                                    None
                                }
                            );

                            Some((attr_name.to_string(), ReplAttrStateV1 { cid, attr }))
                        } else {
                            None
                        }
                    })
                    .collect();

                ReplStateV1::Live { attrs }
            }
            State::Tombstone { at } => ReplStateV1::Tombstone { at: at.into() },
        };

        ReplEntryV1 { uuid, st }
    }

    pub fn rehydrate(&self) -> Result<(EntryChangeState, Eattrs), OperationError> {
        match &self.st {
            ReplStateV1::Live { attrs } => {
                trace!("{:#?}", attrs);
                // We need to build two sets, one for the Entry Change States, and one for the
                // Eattrs.
                let mut changes = BTreeMap::default();
                let mut eattrs = Eattrs::default();

                for (attr_name, ReplAttrStateV1 { cid, attr }) in attrs.iter() {
                    let astring: AttrString = attr_name.as_str().into();
                    let cid: Cid = cid.into();

                    if let Some(attr_value) = attr {
                        let v = valueset::from_repl_v1(attr_value).map_err(|e| {
                            error!("Unable to restore valueset for {}", attr_name);
                            e
                        })?;
                        if eattrs.insert(astring.clone(), v).is_some() {
                            error!(
                                "Impossible eattrs state, attribute {} appears to be duplicated!",
                                attr_name
                            );
                            return Err(OperationError::InvalidEntryState);
                        }
                    }

                    if changes.insert(astring, cid).is_some() {
                        error!(
                            "Impossible changes state, attribute {} appears to be duplicated!",
                            attr_name
                        );
                        return Err(OperationError::InvalidEntryState);
                    }
                }

                let ecstate = EntryChangeState {
                    st: State::Live { changes },
                };
                Ok((ecstate, eattrs))
            }
            ReplStateV1::Tombstone { at } => {
                let at: Cid = at.into();

                let mut eattrs = Eattrs::default();

                let class_ava = vs_iutf8!["object", "tombstone"];
                let last_mod_ava = vs_cid![at.clone()];

                eattrs.insert(AttrString::from("uuid"), vs_uuid![self.uuid]);
                eattrs.insert(AttrString::from("class"), class_ava);
                eattrs.insert(AttrString::from("last_modified_cid"), last_mod_ava);

                let ecstate = EntryChangeState {
                    st: State::Tombstone { at },
                };

                Ok((ecstate, eattrs))
            }
        }
    }
}

// From / Into Entry

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReplRefreshContext {
    V1 {
        domain_version: DomainVersion,
        domain_uuid: Uuid,
        schema_entries: Vec<ReplEntryV1>,
        meta_entries: Vec<ReplEntryV1>,
        entries: Vec<ReplEntryV1>,
    },
}
