use std::borrow::Borrow;
use std::fmt;

mod internal;
mod object;
mod provider;

#[cfg(test)]
pub(crate) use self::internal::KeyObjectInternal;

pub(crate) use self::object::KeyObject;
pub(crate) use self::provider::{
    KeyProvider, KeyProviders, KeyProvidersReadTransaction, KeyProvidersTransaction,
    KeyProvidersWriteTransaction,
};

// 96 bits is sufficent length for key uniqueness. This is just to look up keys, and is
// not a security property of the key
static KID_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyId {
    id: String,
}

impl From<String> for KeyId {
    fn from(mut id: String) -> Self {
        id.truncate(KID_LEN);
        Self { id }
    }
}

impl From<&str> for KeyId {
    fn from(id: &str) -> Self {
        Self::from(id.to_string())
    }
}

impl KeyId {
    pub fn as_str(&self) -> &str {
        self.id.as_str()
    }
}

impl Borrow<String> for KeyId {
    fn borrow(&self) -> &String {
        &self.id
    }
}

impl Borrow<str> for KeyId {
    fn borrow(&self) -> &str {
        self.id.as_str()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}
