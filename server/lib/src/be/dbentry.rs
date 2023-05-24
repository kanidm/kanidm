use std::collections::BTreeMap;
use std::time::Duration;

use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use smartstring::alias::String as AttrString;
use uuid::Uuid;

use crate::be::dbvalue::{DbValueEmailAddressV1, DbValuePhoneNumberV1, DbValueSetV2, DbValueV1};
use crate::prelude::OperationError;

#[derive(Serialize, Deserialize, Debug)]
pub struct DbEntryV1 {
    pub attrs: BTreeMap<AttrString, NonEmpty<DbValueV1>>,
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

fn from_vec_dbval1(attr_val: NonEmpty<DbValueV1>) -> Result<DbValueSetV2, OperationError> {
    match attr_val.first() {
        DbValueV1::Utf8(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Utf8(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Utf8),
        DbValueV1::Iutf8(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Iutf8(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Iutf8),
        DbValueV1::Iname(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Iname(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Iname),
        DbValueV1::Uuid(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Uuid(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Uuid),
        DbValueV1::Bool(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Bool(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Bool),
        DbValueV1::SyntaxType(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::SyntaxType(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::SyntaxType),
        DbValueV1::IndexType(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::IndexType(s) = dbv {
                    u16::try_from(s).map_err(|_| OperationError::InvalidValueState)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::IndexType),
        DbValueV1::Reference(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Reference(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Reference),
        DbValueV1::JsonFilter(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::JsonFilter(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::JsonFilter),
        DbValueV1::Credential(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Credential(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Credential),
        DbValueV1::SecretValue(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::SecretValue(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::SecretValue),
        DbValueV1::SshKey(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::SshKey(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::SshKey),
        DbValueV1::Spn(_, _) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Spn(n, d) = dbv {
                    Ok((n, d))
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Spn),
        DbValueV1::Uint32(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Uint32(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Uint32),
        DbValueV1::Cid(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Cid(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Cid),
        DbValueV1::NsUniqueId(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::NsUniqueId(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::NsUniqueId),
        DbValueV1::DateTime(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::DateTime(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::DateTime),
        DbValueV1::EmailAddress(_) => {
            let mut primary = None;
            let vs: Result<Vec<_>, _> = attr_val
                .into_iter()
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
        DbValueV1::PhoneNumber(_) => {
            let mut primary = None;
            let vs: Result<Vec<_>, _> = attr_val
                .into_iter()
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
        DbValueV1::Address(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Address(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Address),
        DbValueV1::Url(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::Url(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::Url),
        DbValueV1::OauthScope(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::OauthScope(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::OauthScope),
        DbValueV1::OauthScopeMap(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::OauthScopeMap(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::OauthScopeMap),
        DbValueV1::PrivateBinary(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::PrivateBinary(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::PrivateBinary),
        DbValueV1::PublicBinary(_, _) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::PublicBinary(t, s) = dbv {
                    Ok((t, s))
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::PublicBinary),
        DbValueV1::RestrictedString(_) => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::RestrictedString(s) = dbv {
                    Ok(s)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::RestrictedString),
        DbValueV1::IntentToken { u: _, s: _ } => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::IntentToken { u, s } = dbv {
                    Ok((u.as_hyphenated().to_string(), s))
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::IntentToken),
        DbValueV1::TrustedDeviceEnrollment { u: _ } => attr_val
            .into_iter()
            .map(|dbv| {
                if let DbValueV1::TrustedDeviceEnrollment { u } = dbv {
                    Ok(u)
                } else {
                    Err(OperationError::InvalidValueState)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map(DbValueSetV2::TrustedDeviceEnrollment),
        DbValueV1::Session { u: _ } => {
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
                    write!(f, "{k} - [")?;
                    for v in vs {
                        write!(f, "{v:?}, ")?;
                    }
                    write!(f, "], ")?;
                }
                write!(f, "}}")
            }
            DbEntryVers::V2(dbe_v2) => {
                write!(f, "v2 - {{ ")?;
                for (k, vs) in dbe_v2.attrs.iter() {
                    write!(f, "{k} - [")?;
                    write!(f, "{vs:?}, ")?;
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
                            write!(f, "{uuid:?}, ")?;
                        }
                    }
                    None => write!(f, "Uuid(INVALID), ")?,
                };
                if let Some(names) = dbe_v1.attrs.get("name") {
                    for name in names {
                        write!(f, "{name:?}, ")?;
                    }
                }
                if let Some(names) = dbe_v1.attrs.get("attributename") {
                    for name in names {
                        write!(f, "{name:?}, ")?;
                    }
                }
                if let Some(names) = dbe_v1.attrs.get("classname") {
                    for name in names {
                        write!(f, "{name:?}, ")?;
                    }
                }
                write!(f, "}}")
            }
            DbEntryVers::V2(dbe_v2) => {
                write!(f, "v2 - {{ ")?;
                match dbe_v2.attrs.get("uuid") {
                    Some(uuids) => {
                        write!(f, "{uuids:?}, ")?;
                    }
                    None => write!(f, "Uuid(INVALID), ")?,
                };
                if let Some(names) = dbe_v2.attrs.get("name") {
                    write!(f, "{names:?}, ")?;
                }
                if let Some(names) = dbe_v2.attrs.get("attributename") {
                    write!(f, "{names:?}, ")?;
                }
                if let Some(names) = dbe_v2.attrs.get("classname") {
                    write!(f, "{names:?}, ")?;
                }
                write!(f, "}}")
            }
        }
    }
}
