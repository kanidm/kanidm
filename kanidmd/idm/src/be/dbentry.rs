use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use smartstring::alias::String as AttrString;
use uuid::Uuid;

use crate::be::dbvalue::{DbValueEmailAddressV1, DbValuePhoneNumberV1, DbValueSetV2, DbValueV1};
use crate::prelude::OperationError;

#[derive(Serialize, Deserialize, Debug)]
pub struct DbEntryV1 {
    pub attrs: BTreeMap<AttrString, Vec<DbValueV1>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbEntryV2 {
    pub attrs: BTreeMap<AttrString, DbValueSetV2>,
}

// REMEMBER: If you add a new version here, you MUST
// update entry.rs to_dbentry to export to the latest
// type always!!
#[derive(Serialize, Deserialize, Debug)]
pub enum DbEntryVers {
    V1(DbEntryV1),
    V2(DbEntryV2),
}

#[derive(Serialize, Deserialize, Debug)]
// This doesn't need a version since uuid2spn is reindexed - remember if you change this
// though, to change the index version!
pub enum DbIdentSpn {
    #[serde(rename = "SP")]
    Spn(String, String),
    #[serde(rename = "N8")]
    Iname(String),
    #[serde(rename = "UU")]
    Uuid(Uuid),
}

// This is actually what we store into the DB.
#[derive(Serialize, Deserialize)]
pub struct DbEntry {
    pub ent: DbEntryVers,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum DbBackup {
    V1(Vec<DbEntry>),
    V2 {
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        entries: Vec<DbEntry>,
    },
}

fn from_vec_dbval1(attr_val: Vec<DbValueV1>) -> Result<DbValueSetV2, OperationError> {
    // ========================
    //
    let mut viter = attr_val.into_iter().peekable();

    match viter.peek() {
        Some(DbValueV1::Utf8(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Utf8(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Utf8)
        }
        Some(DbValueV1::Iutf8(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Iutf8(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Iutf8)
        }
        Some(DbValueV1::Iname(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Iname(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Iname)
        }
        Some(DbValueV1::Uuid(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Uuid(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Uuid)
        }
        Some(DbValueV1::Bool(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Bool(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Bool)
        }
        Some(DbValueV1::SyntaxType(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::SyntaxType(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::SyntaxType)
        }
        Some(DbValueV1::IndexType(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::IndexType(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::IndexType)
        }
        Some(DbValueV1::Reference(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Reference(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Reference)
        }
        Some(DbValueV1::JsonFilter(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::JsonFilter(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::JsonFilter)
        }
        Some(DbValueV1::Credential(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Credential(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Credential)
        }
        Some(DbValueV1::SecretValue(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::SecretValue(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::SecretValue)
        }
        Some(DbValueV1::SshKey(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::SshKey(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::SshKey)
        }
        Some(DbValueV1::Spn(_, _)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Spn(n, d) = dbv {
                        Ok((n, d))
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Spn)
        }
        Some(DbValueV1::Uint32(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Uint32(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Uint32)
        }
        Some(DbValueV1::Cid(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Cid(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Cid)
        }
        Some(DbValueV1::NsUniqueId(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::NsUniqueId(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::NsUniqueId)
        }
        Some(DbValueV1::DateTime(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::DateTime(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::DateTime)
        }
        Some(DbValueV1::EmailAddress(_)) => {
            let mut primary = None;
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::EmailAddress(DbValueEmailAddressV1 { d, p }) = dbv {
                        if p {
                            primary = Some(d.clone());
                        }
                        Ok(d)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            let primary = primary.ok_or(OperationError::InvalidValueState)?;
            vs.map(|vs| DbValueSetV2::EmailAddress(primary, vs))
        }
        Some(DbValueV1::PhoneNumber(_)) => {
            let mut primary = None;
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::PhoneNumber(DbValuePhoneNumberV1 { d, p }) = dbv {
                        if p {
                            primary = Some(d.clone());
                        }
                        Ok(d)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            let primary = primary.ok_or(OperationError::InvalidValueState)?;
            vs.map(|vs| DbValueSetV2::PhoneNumber(primary, vs))
        }
        Some(DbValueV1::Address(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Address(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Address)
        }
        Some(DbValueV1::Url(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::Url(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::Url)
        }
        Some(DbValueV1::OauthScope(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::OauthScope(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::OauthScope)
        }
        Some(DbValueV1::OauthScopeMap(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::OauthScopeMap(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::OauthScopeMap)
        }
        Some(DbValueV1::PrivateBinary(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::PrivateBinary(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::PrivateBinary)
        }
        Some(DbValueV1::PublicBinary(_, _)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::PublicBinary(t, s) = dbv {
                        Ok((t, s))
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::PublicBinary)
        }
        Some(DbValueV1::RestrictedString(_)) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::RestrictedString(s) = dbv {
                        Ok(s)
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::RestrictedString)
        }
        Some(DbValueV1::IntentToken { u: _, s: _ }) => {
            let vs: Result<Vec<_>, _> = viter
                .map(|dbv| {
                    if let DbValueV1::IntentToken { u, s } = dbv {
                        Ok((u.as_hyphenated().to_string(), s))
                    } else {
                        Err(OperationError::InvalidValueState)
                    }
                })
                .collect();
            vs.map(DbValueSetV2::IntentToken)
        }
        // Neither of these should exist yet.
        Some(DbValueV1::TrustedDeviceEnrollment { u: _ })
        | Some(DbValueV1::Session { u: _ })
        | None => {
            // Shiiiiii
            debug_assert!(false);
            Err(OperationError::InvalidState)
        }
    }
}

impl DbEntry {
    pub(crate) fn convert_to_v2(self) -> Result<Self, OperationError> {
        if let DbEntryVers::V1(dbe) = self.ent {
            dbe.attrs
                .into_iter()
                .filter(|(_attr_name, attr_val)| {
                    // Skip anything that is empty, because our from impl
                    // can't handle it, neither can our dbvaluesetv2
                    !attr_val.is_empty()
                })
                .map(|(attr_name, attr_val)| {
                    from_vec_dbval1(attr_val).map(|attr_val_2| (attr_name, attr_val_2))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map(|attrs| DbEntry {
                    ent: DbEntryVers::V2(DbEntryV2 { attrs }),
                })
        } else {
            Ok(self)
        }
    }
}

impl std::fmt::Debug for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V1(dbe_v1) => {
                write!(f, "v1 - {{ ")?;
                for (k, vs) in dbe_v1.attrs.iter() {
                    write!(f, "{} - [", k)?;
                    for v in vs {
                        write!(f, "{:?}, ", v)?;
                    }
                    write!(f, "], ")?;
                }
                write!(f, "}}")
            }
            DbEntryVers::V2(dbe_v2) => {
                write!(f, "v2 - {{ ")?;
                for (k, vs) in dbe_v2.attrs.iter() {
                    write!(f, "{} - [", k)?;
                    write!(f, "{:?}, ", vs)?;
                    write!(f, "], ")?;
                }
                write!(f, "}}")
            }
        }
    }
}

impl std::fmt::Display for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V1(dbe_v1) => {
                write!(f, "v1 - {{ ")?;
                match dbe_v1.attrs.get("uuid") {
                    Some(uuids) => {
                        for uuid in uuids {
                            write!(f, "{:?}, ", uuid)?;
                        }
                    }
                    None => write!(f, "Uuid(INVALID), ")?,
                };
                if let Some(names) = dbe_v1.attrs.get("name") {
                    for name in names {
                        write!(f, "{:?}, ", name)?;
                    }
                }
                if let Some(names) = dbe_v1.attrs.get("attributename") {
                    for name in names {
                        write!(f, "{:?}, ", name)?;
                    }
                }
                if let Some(names) = dbe_v1.attrs.get("classname") {
                    for name in names {
                        write!(f, "{:?}, ", name)?;
                    }
                }
                write!(f, "}}")
            }
            DbEntryVers::V2(dbe_v2) => {
                write!(f, "v2 - {{ ")?;
                match dbe_v2.attrs.get("uuid") {
                    Some(uuids) => {
                        write!(f, "{:?}, ", uuids)?;
                    }
                    None => write!(f, "Uuid(INVALID), ")?,
                };
                if let Some(names) = dbe_v2.attrs.get("name") {
                    write!(f, "{:?}, ", names)?;
                }
                if let Some(names) = dbe_v2.attrs.get("attributename") {
                    write!(f, "{:?}, ", names)?;
                }
                if let Some(names) = dbe_v2.attrs.get("classname") {
                    write!(f, "{:?}, ", names)?;
                }
                write!(f, "}}")
            }
        }
    }
}
