use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use smartstring::alias::String as AttrString;
use uuid::Uuid;
use nonempty::NonEmpty;

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
    match attr_val.head {
        DbValueV1::Utf8(s) => {
            Ok(DbValueSetV2::Utf8(vec!(s)))
        }
        DbValueV1::Iutf8(s) => {
            Ok(DbValueSetV2::Iutf8(vec!(s)))
        }
        DbValueV1::Iname(s) => {
            Ok(DbValueSetV2::Iname(vec!(s)))
        }
        DbValueV1::Uuid(s) => {
            Ok(DbValueSetV2::Uuid(vec!(s)))
        }
        DbValueV1::Bool(s) => {
            Ok(DbValueSetV2::Bool(vec!(s)))
        }
        DbValueV1::SyntaxType(s) => {
            Ok(DbValueSetV2::SyntaxType(vec!(s)))
        }
        DbValueV1::IndexType(s) => {
            if let Ok(s_u16) = u16::try_from(s) {
                Ok(DbValueSetV2::IndexType(vec!(s_u16)))
            } else {
                Err(OperationError::InvalidValueState)
            }
        }
        DbValueV1::Reference(s) => {
            Ok(DbValueSetV2::Reference(vec!(s)))
        }
        DbValueV1::JsonFilter(s) => {
            Ok(DbValueSetV2::JsonFilter(vec!(s)))
        }
        DbValueV1::Credential(s) => {
            Ok(DbValueSetV2::Credential(vec!(s)))
        }
        DbValueV1::SecretValue(s) => {
            Ok(DbValueSetV2::SecretValue(vec!(s)))
        }
        DbValueV1::SshKey(s) => {
            Ok(DbValueSetV2::SshKey(vec!(s)))
        }
        DbValueV1::Spn(n, d) => {
            Ok(DbValueSetV2::Spn(vec!((n, d))))
        }
        DbValueV1::Uint32(s) => {
            Ok(DbValueSetV2::Uint32(vec!(s)))
        }
        DbValueV1::Cid(s) => {
            Ok(DbValueSetV2::Cid(vec!(s)))
        }
        DbValueV1::NsUniqueId(s) => {
            Ok(DbValueSetV2::NsUniqueId(vec!(s)))
        }
        DbValueV1::DateTime(s) => {
            Ok(DbValueSetV2::DateTime(vec!(s)))
        }
        DbValueV1::EmailAddress(DbValueEmailAddressV1 { d, p }) => {
            if p {
                Ok(DbValueSetV2::EmailAddress(d.clone(), vec!(d)))
            } else {
                Err(OperationError::InvalidValueState)
            }
        }
        DbValueV1::PhoneNumber(DbValuePhoneNumberV1 { d, p }) => {
            if p {
                Ok(DbValueSetV2::PhoneNumber(d.clone(), vec!(d)))
            } else {
                Err(OperationError::InvalidValueState)
            }
        }
        DbValueV1::Address(s) => {
            Ok(DbValueSetV2::Address(vec!(s)))
        }
        DbValueV1::Url(s) => {
            Ok(DbValueSetV2::Url(vec!(s)))
        }
        DbValueV1::OauthScope(s) => {
            Ok(DbValueSetV2::OauthScope(vec!(s)))
        }
        DbValueV1::OauthScopeMap(s) => {
            Ok(DbValueSetV2::OauthScopeMap(vec!(s)))
        }
        DbValueV1::PrivateBinary(s) => {
            Ok(DbValueSetV2::PrivateBinary(vec!(s)))
        }
        DbValueV1::PublicBinary(t, s) => {
            Ok(DbValueSetV2::PublicBinary(vec!((t, s))))
        }
        DbValueV1::RestrictedString(s) => {
            Ok(DbValueSetV2::RestrictedString(vec!(s)))
        }
        DbValueV1::IntentToken { u, s} => {
            Ok(DbValueSetV2::IntentToken(vec!((u.as_hyphenated().to_string(), s))))
        }
        DbValueV1::TrustedDeviceEnrollment { u } => {
            Ok(DbValueSetV2::TrustedDeviceEnrollment(vec!(u)))
        }
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
