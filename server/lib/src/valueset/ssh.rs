use crate::be::dbvalue::DbValueTaggedStringV1;
use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::utils::trigraph_iter;
use crate::valueset::{
    DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut,
};
use kanidm_proto::scim_v1::JsonValue;
use kanidm_proto::scim_v1::ScimSshPublicKey;
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct ValueSetSshKey {
    map: BTreeMap<String, SshPublicKey>,
}

impl ValueSetSshKey {
    pub fn new(t: String, k: SshPublicKey) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, k);
        Box::new(ValueSetSshKey { map })
    }

    pub fn push(&mut self, t: String, k: SshPublicKey) -> bool {
        self.map.insert(t, k).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueTaggedStringV1>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .filter_map(|DbValueTaggedStringV1 { tag, data }| {
                SshPublicKey::from_string(&data)
                    .map_err(|err| {
                        warn!(%tag, ?err, "discarding corrupted ssh public key");
                    })
                    .map(|pk| (tag, pk))
                    .ok()
            })
            .collect();
        Ok(Box::new(ValueSetSshKey { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, SshPublicKey)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetSshKey { map }))
    }
}

impl ValueSetScimPut for ValueSetSshKey {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value: Vec<ScimSshPublicKey> = serde_json::from_value(value).map_err(|err| {
            error!(?err, "SCIM Ssh Public Key syntax invalid");
            OperationError::SC0024SshPublicKeySyntaxInvalid
        })?;

        let map = value
            .into_iter()
            .map(|ScimSshPublicKey { label, value }| (label, value))
            .collect();

        Ok(ValueSetResolveStatus::Resolved(Box::new(ValueSetSshKey {
            map,
        })))
    }
}

impl ValueSetT for ValueSetSshKey {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::SshKey(t, k) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(t) {
                    e.insert(k);
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
            PartialValue::SshKey(t) => self.map.remove(t.as_str()).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::SshKey(t) => self.map.contains_key(t.as_str()),
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
        SyntaxType::SshKey
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map.iter().all(|(s, _key)| {
            Value::validate_str_escapes(s)
                // && Value::validate_iname(s)
                && Value::validate_singleline(s)
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().map(|(tag, pk)| format!("{}: {}", tag, pk)))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(label, value)| ScimSshPublicKey {
                    label: label.clone(),
                    value: value.clone(),
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::SshKey(
            self.map
                .iter()
                .map(|(tag, key)| DbValueTaggedStringV1 {
                    tag: tag.clone(),
                    data: key.to_string(),
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::SshKey))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(t, k)| Value::SshKey(t.clone(), k.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_sshkey_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_sshkey_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_sshkey_map(&self) -> Option<&BTreeMap<String, SshPublicKey>> {
        Some(&self.map)
    }

    fn get_ssh_tag(&self, tag: &str) -> Option<&SshPublicKey> {
        self.map.get(tag)
    }

    fn as_sshpubkey_string_iter(&self) -> Option<Box<dyn Iterator<Item = String> + '_>> {
        Some(Box::new(self.map.values().map(|pk| pk.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::{SshPublicKey, ValueSetSshKey};
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_ssh_public_key() {
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag== william@a",
        "methyst");

        let vs: ValueSet = ValueSetSshKey::new(
            "label".to_string(),
            SshPublicKey::from_string(ecdsa).unwrap(),
        );

        let data = r#"
[
  {
    "label": "label",
    "value": "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3BtOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81lzPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag== william@amethyst"
  }
]
        "#;
        crate::valueset::scim_json_reflexive(&vs, data);

        // Test that we can parse json values into a valueset.
        crate::valueset::scim_json_put_reflexive::<ValueSetSshKey>(&vs, &[])
    }

    #[test]
    /// this is a test case for bad characters in SSH keys
    fn test_invalid_character() {
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEÀAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        //                                                                      ^ note the À here
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0è15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag== william@a",
        "methyst");
        println!("bytes of À {:?}", "À".as_bytes());
        let found_index = ecdsa.find("À").expect("Failed to find è in string");
        assert_eq!(found_index, 51, "Expected index 51");
        let bad_ssh_error = SshPublicKey::from_string(ecdsa);

        assert!(
            bad_ssh_error.is_err(),
            "Expected error, but got: {:?}",
            bad_ssh_error
        );
        if let Err(err) = bad_ssh_error {
            assert_eq!(
                err.to_string(),
                format!("Invalid symbol 195, offset {}.", found_index - 20)
            ); // the offset is 31 because the string has a 20 character leading key type plus the space
        }
    }

    #[test]
    /// this is a test case for bad characters in SSH keys
    fn test_assert_comments() {
        // Comment is okay.
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag== william@a",
        "methyst");

        let _ = SshPublicKey::from_string(ecdsa).unwrap();

        // No comment is okay.
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag==");

        let _ = SshPublicKey::from_string(ecdsa).unwrap();

        // No comment is okay (spaces to end of line)
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag==     ");

        let _ = SshPublicKey::from_string(ecdsa).unwrap();

        // Comment may have spaces
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag==  I'm a giraffe! ");

        let _ = SshPublicKey::from_string(ecdsa).unwrap();
    }
}
