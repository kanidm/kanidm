use std::collections::{BTreeMap, BTreeSet};

use compact_jwt::JwsSigner;
use dyn_clone::DynClone;
use hashbrown::HashSet;
use kanidm_proto::v1::Filter as ProtoFilter;
use kanidm_proto::v1::UiHint;
use smolset::SmolSet;
use time::OffsetDateTime;
// use std::fmt::Debug;
use webauthn_rs::prelude::DeviceKey as DeviceKeyV4;
use webauthn_rs::prelude::Passkey as PasskeyV4;

use crate::be::dbvalue::DbValueSetV2;
use crate::credential::Credential;
use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::schema::SchemaAttribute;
use crate::value::{Address, IntentTokenState, Oauth2Session, Session};

mod address;
mod binary;
mod bool;
mod cid;
mod cred;
mod datetime;
mod iname;
mod index;
mod iutf8;
mod json;
mod jws;
mod nsuniqueid;
mod oauth;
mod restricted;
mod secret;
mod session;
mod spn;
mod ssh;
mod syntax;
mod uihint;
mod uint32;
mod url;
mod utf8;
mod uuid;

pub use self::address::{ValueSetAddress, ValueSetEmailAddress};
pub use self::binary::{ValueSetPrivateBinary, ValueSetPublicBinary};
pub use self::bool::ValueSetBool;
pub use self::cid::ValueSetCid;
pub use self::cred::{ValueSetCredential, ValueSetDeviceKey, ValueSetIntentToken, ValueSetPasskey};
pub use self::datetime::ValueSetDateTime;
pub use self::iname::ValueSetIname;
pub use self::index::ValueSetIndex;
pub use self::iutf8::ValueSetIutf8;
pub use self::json::ValueSetJsonFilter;
pub use self::jws::{ValueSetJwsKeyEs256, ValueSetJwsKeyRs256};
pub use self::nsuniqueid::ValueSetNsUniqueId;
pub use self::oauth::{ValueSetOauthScope, ValueSetOauthScopeMap};
pub use self::restricted::ValueSetRestricted;
pub use self::secret::ValueSetSecret;
pub use self::session::{ValueSetOauth2Session, ValueSetSession};
pub use self::spn::ValueSetSpn;
pub use self::ssh::ValueSetSshKey;
pub use self::syntax::ValueSetSyntax;
pub use self::uihint::ValueSetUiHint;
pub use self::uint32::ValueSetUint32;
pub use self::url::ValueSetUrl;
pub use self::utf8::ValueSetUtf8;
pub use self::uuid::{ValueSetRefer, ValueSetUuid};

pub type ValueSet = Box<dyn ValueSetT + Send + Sync + 'static>;

dyn_clone::clone_trait_object!(ValueSetT);

pub trait ValueSetT: std::fmt::Debug + DynClone {
    /// # Safety
    /// This is unsafe as you are unable to distinguish the case between
    /// the value already existing, OR the value being an incorrect type to add
    /// to the set.
    unsafe fn insert(&mut self, value: Value) -> bool {
        self.insert_checked(value).unwrap_or(false)
    }

    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError>;

    fn clear(&mut self);

    fn remove(&mut self, pv: &PartialValue) -> bool;

    fn contains(&self, pv: &PartialValue) -> bool;

    fn substring(&self, pv: &PartialValue) -> bool;

    fn lessthan(&self, pv: &PartialValue) -> bool;

    fn len(&self) -> usize;

    fn generate_idx_eq_keys(&self) -> Vec<String>;

    fn syntax(&self) -> SyntaxType;

    fn validate(&self, schema_attr: &SchemaAttribute) -> bool;

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_>;

    fn to_db_valueset_v2(&self) -> DbValueSetV2;

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_>;

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_>;

    fn equal(&self, other: &ValueSet) -> bool;

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn migrate_iutf8_iname(&self) -> Result<Option<ValueSet>, OperationError> {
        debug_assert!(false);
        Ok(None)
    }

    fn get_ssh_tag(&self, _tag: &str) -> Option<&str> {
        None
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        None
    }

    fn as_utf8_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!("as_utf8_iter should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn as_iutf8_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!("as_iutf8_iter should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn as_iname_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!("as_iname_iter should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn as_indextype_iter(&self) -> Option<Box<dyn Iterator<Item = IndexType> + '_>> {
        error!(
            "as_indextype_set should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn as_restricted_string_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!(
            "as_restricted_string_iter should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn as_oauthscope_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!(
            "as_oauthscope_iter should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn as_sshpubkey_str_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        None
    }

    fn as_email_str_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        None
    }

    fn as_utf8_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_iutf8_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_iname_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_uuid_set(&self) -> Option<&SmolSet<[Uuid; 1]>> {
        None
    }

    fn as_refer_set(&self) -> Option<&BTreeSet<Uuid>> {
        None
    }

    fn as_bool_set(&self) -> Option<&SmolSet<[bool; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_uint32_set(&self) -> Option<&SmolSet<[u32; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_syntax_set(&self) -> Option<&SmolSet<[SyntaxType; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_index_set(&self) -> Option<&SmolSet<[IndexType; 3]>> {
        debug_assert!(false);
        None
    }

    fn as_secret_set(&self) -> Option<&SmolSet<[String; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_restricted_string_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_spn_set(&self) -> Option<&SmolSet<[(String, String); 1]>> {
        debug_assert!(false);
        None
    }

    fn as_cid_set(&self) -> Option<&SmolSet<[Cid; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_json_filter_set(&self) -> Option<&SmolSet<[ProtoFilter; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_nsuniqueid_set(&self) -> Option<&SmolSet<[String; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_url_set(&self) -> Option<&SmolSet<[Url; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_datetime_set(&self) -> Option<&SmolSet<[OffsetDateTime; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_private_binary_set(&self) -> Option<&SmolSet<[Vec<u8>; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_oauthscope_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_address_set(&self) -> Option<&SmolSet<[Address; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_credential_map(&self) -> Option<&BTreeMap<String, Credential>> {
        debug_assert!(false);
        None
    }

    fn as_emailaddress_set(&self) -> Option<(&String, &BTreeSet<String>)> {
        debug_assert!(false);
        None
    }

    fn as_sshkey_map(&self) -> Option<&BTreeMap<String, String>> {
        None
    }

    fn as_oauthscopemap(&self) -> Option<&BTreeMap<Uuid, BTreeSet<String>>> {
        /*
        error!(
            "as_oauthscopemap should not be called on {:?}",
            self.syntax()
        );
        */
        None
    }

    fn as_publicbinary_map(&self) -> Option<&BTreeMap<String, Vec<u8>>> {
        debug_assert!(false);
        None
    }

    fn as_intenttoken_map(&self) -> Option<&BTreeMap<String, IntentTokenState>> {
        debug_assert!(false);
        None
    }

    fn as_passkey_map(&self) -> Option<&BTreeMap<Uuid, (String, PasskeyV4)>> {
        debug_assert!(false);
        None
    }

    fn as_devicekey_map(&self) -> Option<&BTreeMap<Uuid, (String, DeviceKeyV4)>> {
        debug_assert!(false);
        None
    }

    fn to_value_single(&self) -> Option<Value> {
        if self.len() != 1 {
            None
        } else {
            self.to_value_iter().take(1).next()
        }
    }

    fn to_proto_string_single(&self) -> Option<String> {
        if self.len() != 1 {
            None
        } else {
            self.to_proto_string_clone_iter().take(1).next()
        }
    }

    fn to_uuid_single(&self) -> Option<Uuid> {
        error!("to_uuid_single should not be called on {:?}", self.syntax());
        None
    }

    fn to_refer_single(&self) -> Option<Uuid> {
        error!(
            "to_refer_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_bool_single(&self) -> Option<bool> {
        error!("to_bool_single should not be called on {:?}", self.syntax());
        None
    }

    fn to_uint32_single(&self) -> Option<u32> {
        error!(
            "to_uint32_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_syntaxtype_single(&self) -> Option<SyntaxType> {
        error!(
            "to_syntaxtype_single should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn to_credential_single(&self) -> Option<&Credential> {
        error!(
            "to_credential_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_secret_single(&self) -> Option<&str> {
        error!(
            "to_secret_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_restricted_string_single(&self) -> Option<&str> {
        error!(
            "to_restricted_string_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_utf8_single(&self) -> Option<&str> {
        error!("to_utf8_single should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn to_iutf8_single(&self) -> Option<&str> {
        error!(
            "to_iutf8_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_iname_single(&self) -> Option<&str> {
        error!(
            "to_iname_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_datetime_single(&self) -> Option<OffsetDateTime> {
        error!(
            "to_datetime_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_url_single(&self) -> Option<&Url> {
        error!("to_url_single should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn to_json_filter_single(&self) -> Option<&ProtoFilter> {
        error!(
            "to_json_filter_single should not be called on {:?}",
            self.syntax()
        );
        // debug_assert!(false);
        None
    }

    fn to_email_address_primary_str(&self) -> Option<&str> {
        debug_assert!(false);
        None
    }

    fn to_private_binary_single(&self) -> Option<&[u8]> {
        debug_assert!(false);
        None
    }

    fn to_passkey_single(&self) -> Option<&PasskeyV4> {
        debug_assert!(false);
        None
    }

    fn to_devicekey_single(&self) -> Option<&DeviceKeyV4> {
        debug_assert!(false);
        None
    }

    fn as_session_map(&self) -> Option<&BTreeMap<Uuid, Session>> {
        debug_assert!(false);
        None
    }

    fn as_oauth2session_map(&self) -> Option<&BTreeMap<Uuid, Oauth2Session>> {
        debug_assert!(false);
        None
    }

    fn to_jws_key_es256_single(&self) -> Option<&JwsSigner> {
        debug_assert!(false);
        None
    }

    fn as_jws_key_es256_set(&self) -> Option<&HashSet<JwsSigner>> {
        debug_assert!(false);
        None
    }

    fn to_jws_key_rs256_single(&self) -> Option<&JwsSigner> {
        debug_assert!(false);
        None
    }

    fn as_jws_key_rs256_set(&self) -> Option<&HashSet<JwsSigner>> {
        debug_assert!(false);
        None
    }

    fn as_uihint_set(&self) -> Option<&BTreeSet<UiHint>> {
        debug_assert!(false);
        None
    }

    fn as_uihint_iter(&self) -> Option<Box<dyn Iterator<Item = UiHint> + '_>> {
        debug_assert!(false);
        None
    }
}

impl PartialEq for ValueSet {
    fn eq(&self, other: &ValueSet) -> bool {
        self.equal(other)
    }
}

pub fn uuid_to_proto_string(u: Uuid) -> String {
    u.as_hyphenated().to_string()
}

pub fn from_result_value_iter(
    mut iter: impl Iterator<Item = Result<Value, OperationError>>,
) -> Result<ValueSet, OperationError> {
    let init = if let Some(v) = iter.next() {
        v
    } else {
        admin_error!("Empty value iterator");
        return Err(OperationError::InvalidValueState);
    };

    let init = init?;

    let mut vs: ValueSet = match init {
        Value::Utf8(s) => ValueSetUtf8::new(s),
        Value::Iutf8(s) => ValueSetIutf8::new(&s),
        Value::Iname(s) => ValueSetIname::new(&s),
        Value::Uuid(u) => ValueSetUuid::new(u),
        Value::Refer(u) => ValueSetRefer::new(u),
        Value::Bool(u) => ValueSetBool::new(u),
        Value::Uint32(u) => ValueSetUint32::new(u),
        Value::Syntax(u) => ValueSetSyntax::new(u),
        Value::Index(u) => ValueSetIndex::new(u),
        Value::SecretValue(u) => ValueSetSecret::new(u),
        Value::RestrictedString(u) => ValueSetRestricted::new(u),
        Value::Spn(n, d) => ValueSetSpn::new((n, d)),
        Value::Cid(u) => ValueSetCid::new(u),
        Value::JsonFilt(u) => ValueSetJsonFilter::new(u),
        Value::Nsuniqueid(u) => ValueSetNsUniqueId::new(u),
        Value::Url(u) => ValueSetUrl::new(u),
        Value::DateTime(u) => ValueSetDateTime::new(u),
        Value::PrivateBinary(u) => ValueSetPrivateBinary::new(u),
        Value::OauthScope(u) => ValueSetOauthScope::new(u),
        Value::Address(u) => ValueSetAddress::new(u),
        Value::Cred(t, c) => ValueSetCredential::new(t, c),
        Value::SshKey(t, k) => ValueSetSshKey::new(t, k),
        Value::OauthScopeMap(u, m) => ValueSetOauthScopeMap::new(u, m),
        Value::PublicBinary(t, b) => ValueSetPublicBinary::new(t, b),
        Value::IntentToken(u, s) => ValueSetIntentToken::new(u, s),
        Value::EmailAddress(a, _) => ValueSetEmailAddress::new(a),
        Value::UiHint(u) => ValueSetUiHint::new(u),
        Value::PhoneNumber(_, _)
        | Value::Passkey(_, _, _)
        | Value::DeviceKey(_, _, _)
        | Value::TrustedDeviceEnrollment(_)
        | Value::Session(_, _)
        | Value::Oauth2Session(_, _)
        | Value::JwsKeyEs256(_)
        | Value::JwsKeyRs256(_) => {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        }
    };

    for maybe_v in iter {
        let v = maybe_v?;
        // Need to error if wrong type (but shouldn't be due to the way qs works)
        vs.insert_checked(v)?;
    }
    Ok(vs)
}

pub fn from_value_iter(mut iter: impl Iterator<Item = Value>) -> Result<ValueSet, OperationError> {
    let init = if let Some(v) = iter.next() {
        v
    } else {
        admin_error!("Empty value iterator");
        return Err(OperationError::InvalidValueState);
    };

    let mut vs: ValueSet = match init {
        Value::Utf8(s) => ValueSetUtf8::new(s),
        Value::Iutf8(s) => ValueSetIutf8::new(&s),
        Value::Iname(s) => ValueSetIname::new(&s),
        Value::Uuid(u) => ValueSetUuid::new(u),
        Value::Refer(u) => ValueSetRefer::new(u),
        Value::Bool(u) => ValueSetBool::new(u),
        Value::Uint32(u) => ValueSetUint32::new(u),
        Value::Syntax(u) => ValueSetSyntax::new(u),
        Value::Index(u) => ValueSetIndex::new(u),
        Value::SecretValue(u) => ValueSetSecret::new(u),
        Value::RestrictedString(u) => ValueSetRestricted::new(u),
        Value::Spn(n, d) => ValueSetSpn::new((n, d)),
        Value::Cid(u) => ValueSetCid::new(u),
        Value::JsonFilt(u) => ValueSetJsonFilter::new(u),
        Value::Nsuniqueid(u) => ValueSetNsUniqueId::new(u),
        Value::Url(u) => ValueSetUrl::new(u),
        Value::DateTime(u) => ValueSetDateTime::new(u),
        Value::PrivateBinary(u) => ValueSetPrivateBinary::new(u),
        Value::OauthScope(u) => ValueSetOauthScope::new(u),
        Value::Address(u) => ValueSetAddress::new(u),
        Value::Cred(t, c) => ValueSetCredential::new(t, c),
        Value::SshKey(t, k) => ValueSetSshKey::new(t, k),
        Value::OauthScopeMap(u, m) => ValueSetOauthScopeMap::new(u, m),
        Value::PublicBinary(t, b) => ValueSetPublicBinary::new(t, b),
        Value::IntentToken(u, s) => ValueSetIntentToken::new(u, s),
        Value::EmailAddress(a, _) => ValueSetEmailAddress::new(a),
        Value::Passkey(u, t, k) => ValueSetPasskey::new(u, t, k),
        Value::DeviceKey(u, t, k) => ValueSetDeviceKey::new(u, t, k),
        Value::JwsKeyEs256(k) => ValueSetJwsKeyEs256::new(k),
        Value::JwsKeyRs256(k) => ValueSetJwsKeyRs256::new(k),
        Value::Session(u, m) => ValueSetSession::new(u, m),
        Value::Oauth2Session(u, m) => ValueSetOauth2Session::new(u, m),
        Value::UiHint(u) => ValueSetUiHint::new(u),
        Value::PhoneNumber(_, _) | Value::TrustedDeviceEnrollment(_) => {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        }
    };

    for v in iter {
        vs.insert_checked(v)?;
    }
    Ok(vs)
}

pub fn from_db_valueset_v2(dbvs: DbValueSetV2) -> Result<ValueSet, OperationError> {
    match dbvs {
        DbValueSetV2::Utf8(set) => ValueSetUtf8::from_dbvs2(set),
        DbValueSetV2::Iutf8(set) => ValueSetIutf8::from_dbvs2(set),
        DbValueSetV2::Iname(set) => ValueSetIname::from_dbvs2(set),
        DbValueSetV2::Uuid(set) => ValueSetUuid::from_dbvs2(set),
        DbValueSetV2::Reference(set) => ValueSetRefer::from_dbvs2(set),
        DbValueSetV2::Bool(set) => ValueSetBool::from_dbvs2(set),
        DbValueSetV2::Uint32(set) => ValueSetUint32::from_dbvs2(set),
        DbValueSetV2::SyntaxType(set) => ValueSetSyntax::from_dbvs2(set),
        DbValueSetV2::IndexType(set) => ValueSetIndex::from_dbvs2(set),
        DbValueSetV2::SecretValue(set) => ValueSetSecret::from_dbvs2(set),
        DbValueSetV2::RestrictedString(set) => ValueSetRestricted::from_dbvs2(set),
        DbValueSetV2::Spn(set) => ValueSetSpn::from_dbvs2(set),
        DbValueSetV2::Cid(set) => ValueSetCid::from_dbvs2(set),
        DbValueSetV2::JsonFilter(set) => ValueSetJsonFilter::from_dbvs2(set),
        DbValueSetV2::NsUniqueId(set) => ValueSetNsUniqueId::from_dbvs2(set),
        DbValueSetV2::Url(set) => ValueSetUrl::from_dbvs2(set),
        DbValueSetV2::DateTime(set) => ValueSetDateTime::from_dbvs2(set),
        DbValueSetV2::PrivateBinary(set) => ValueSetPrivateBinary::from_dbvs2(set),
        DbValueSetV2::OauthScope(set) => ValueSetOauthScope::from_dbvs2(set),
        DbValueSetV2::Address(set) => ValueSetAddress::from_dbvs2(set),
        DbValueSetV2::Credential(set) => ValueSetCredential::from_dbvs2(set),
        DbValueSetV2::SshKey(set) => ValueSetSshKey::from_dbvs2(set),
        DbValueSetV2::OauthScopeMap(set) => ValueSetOauthScopeMap::from_dbvs2(set),
        DbValueSetV2::PublicBinary(set) => ValueSetPublicBinary::from_dbvs2(set),
        DbValueSetV2::IntentToken(set) => ValueSetIntentToken::from_dbvs2(set),
        DbValueSetV2::EmailAddress(primary, set) => ValueSetEmailAddress::from_dbvs2(primary, set),
        DbValueSetV2::Passkey(set) => ValueSetPasskey::from_dbvs2(set),
        DbValueSetV2::DeviceKey(set) => ValueSetDeviceKey::from_dbvs2(set),
        DbValueSetV2::Session(set) => ValueSetSession::from_dbvs2(set),
        DbValueSetV2::Oauth2Session(set) => ValueSetOauth2Session::from_dbvs2(set),
        DbValueSetV2::JwsKeyEs256(set) => ValueSetJwsKeyEs256::from_dbvs2(&set),
        DbValueSetV2::JwsKeyRs256(set) => ValueSetJwsKeyEs256::from_dbvs2(&set),
        DbValueSetV2::UiHint(set) => ValueSetUiHint::from_dbvs2(set),
        DbValueSetV2::PhoneNumber(_, _) | DbValueSetV2::TrustedDeviceEnrollment(_) => {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }
}
