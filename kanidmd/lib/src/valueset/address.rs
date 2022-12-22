use std::collections::BTreeSet;

use smolset::SmolSet;

use crate::be::dbvalue::DbValueAddressV1;
use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::value::Address;
use crate::valueset::{DbValueSetV2, ValueSet};

#[derive(Debug, Clone)]
pub struct ValueSetAddress {
    set: SmolSet<[Address; 1]>,
}

impl ValueSetAddress {
    pub fn new(b: Address) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetAddress { set })
    }

    pub fn push(&mut self, b: Address) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<DbValueAddressV1>) -> Result<ValueSet, OperationError> {
        let set = data
            .into_iter()
            .map(
                |DbValueAddressV1 {
                     formatted,
                     street_address,
                     locality,
                     region,
                     postal_code,
                     country,
                 }| {
                    Address {
                        formatted,
                        street_address,
                        locality,
                        region,
                        postal_code,
                        country,
                    }
                },
            )
            .collect();
        Ok(Box::new(ValueSetAddress { set }))
    }
}

impl FromIterator<Address> for Option<Box<ValueSetAddress>> {
    fn from_iter<T>(iter: T) -> Option<Box<ValueSetAddress>>
    where
        T: IntoIterator<Item = Address>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetAddress { set }))
    }
}

impl ValueSetT for ValueSetAddress {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Address(u) => Ok(self.set.insert(u)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Address(_) => {
                unreachable!()
            }
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Address(_) => {
                unreachable!()
            }
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        unreachable!();
        // self.set.iter().map(|b| b.to_string()).collect()
    }

    fn syntax(&self) -> SyntaxType {
        unreachable!();
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|a| a.formatted.clone()))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Address(
            self.set
                .iter()
                .map(|a| DbValueAddressV1 {
                    formatted: a.formatted.clone(),
                    street_address: a.street_address.clone(),
                    locality: a.locality.clone(),
                    region: a.region.clone(),
                    postal_code: a.postal_code.clone(),
                    country: a.country.clone(),
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.set
                .iter()
                .map(|s| PartialValue::Address(s.formatted.clone())),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::Address))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_address_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_address_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    /*
    fn to_address_single(&self) -> Option<&Address> {
        if self.set.len() == 1 {
            self.set.iter().take(1).next()
        } else {
            None
        }
    }
    */

    fn as_address_set(&self) -> Option<&SmolSet<[Address; 1]>> {
        Some(&self.set)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetEmailAddress {
    primary: String,
    set: BTreeSet<String>,
}

impl ValueSetEmailAddress {
    pub fn new(primary: String) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(primary.clone());
        Box::new(ValueSetEmailAddress { primary, set })
    }

    pub fn push(&mut self, a: String, primary: bool) -> bool {
        if primary {
            self.primary = a.clone();
        }
        self.set.insert(a)
    }

    pub fn from_dbvs2(primary: String, data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set: BTreeSet<_> = data.into_iter().collect();

        if set.contains(&primary) {
            Ok(Box::new(ValueSetEmailAddress { primary, set }))
        } else {
            Err(OperationError::InvalidValueState)
        }
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetEmailAddress>>
    where
        T: IntoIterator<Item = (String, bool)>,
    {
        let mut primary = None;
        let set = iter
            .into_iter()
            .map(|(a, p)| {
                if p {
                    primary = Some(a.clone());
                }
                a
            })
            .collect();

        if let Some(primary) = primary {
            Some(Box::new(ValueSetEmailAddress { primary, set }))
        } else {
            set.iter()
                .next()
                .cloned()
                .map(|primary| Box::new(ValueSetEmailAddress { primary, set }))
        }
    }
}

impl ValueSetT for ValueSetEmailAddress {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::EmailAddress(a, p) => {
                // if the set was empty, we need to force update primary.
                if p || self.set.is_empty() {
                    self.primary = a.clone();
                }
                Ok(self.set.insert(a))
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::EmailAddress(a) => {
                let r = self.set.remove(a);
                if &self.primary == a {
                    // if we can, inject another former address into primary.
                    if let Some(n) = self.set.iter().next().cloned() {
                        self.primary = n
                    }
                }
                r
            }
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::EmailAddress(a) => self.set.contains(a),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::EmailAddress
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.contains(&self.primary)
            && self
                .set
                .iter()
                .all(|mail| validator::validate_email(mail.as_str()))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            std::iter::once(self.primary.clone()).chain(
                self.set
                    .iter()
                    .filter(|mail| **mail != self.primary)
                    .cloned(),
            ),
        )
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::EmailAddress(self.primary.clone(), self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::EmailAddress))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(|a| {
            let p = a == self.primary;
            Value::EmailAddress(a, p)
        }))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some((p_b, set_b)) = other.as_emailaddress_set() {
            &self.set == set_b && &self.primary == p_b
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some((_p, set_b)) = other.as_emailaddress_set() {
            mergesets!(self.set, set_b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_emailaddress_set(&self) -> Option<(&String, &BTreeSet<String>)> {
        if self.set.is_empty() {
            None
        } else {
            Some((&self.primary, &self.set))
        }
    }

    fn to_email_address_primary_str(&self) -> Option<&str> {
        if self.set.is_empty() {
            None
        } else {
            Some(self.primary.as_str())
        }
    }

    fn as_email_str_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        Some(Box::new(self.set.iter().map(|s| s.as_str())))
    }
}

/*
#[derive(Debug, Clone)]
pub struct ValueSetPhoneNumber {
    primary: String,
    set: BTreeSet<String>,
}
*/

#[cfg(test)]
mod tests {
    use super::ValueSetEmailAddress;
    use crate::value::{PartialValue, Value};
    use crate::valueset::{self, ValueSet};

    #[test]
    fn test_valueset_emailaddress() {
        // Can be created
        //
        let mut vs: ValueSet = ValueSetEmailAddress::new("claire@example.com".to_string());

        assert!(vs.len() == 1);
        assert!(vs.to_email_address_primary_str() == Some("claire@example.com"));

        // Add another, still not primary.
        assert!(
            vs.insert_checked(
                Value::new_email_address_s("alice@example.com").expect("Invalid Email")
            ) == Ok(true)
        );

        assert!(vs.len() == 2);
        assert!(vs.to_email_address_primary_str() == Some("claire@example.com"));

        // Update primary
        assert!(
            vs.insert_checked(
                Value::new_email_address_primary_s("primary@example.com").expect("Invalid Email")
            ) == Ok(true)
        );
        assert!(vs.to_email_address_primary_str() == Some("primary@example.com"));

        // Restore from dbv1, ensure correct primary
        let vs2 = valueset::from_db_valueset_v2(vs.to_db_valueset_v2())
            .expect("Failed to construct vs2 from dbvalue");

        assert!(&vs == &vs2);
        assert!(vs.to_email_address_primary_str() == vs2.to_email_address_primary_str());

        // Remove primary, assert it's gone and that the "first" address is assigned.
        assert!(vs.remove(&PartialValue::new_email_address_s("primary@example.com")));
        assert!(vs.len() == 2);
        assert!(vs.to_email_address_primary_str() == Some("alice@example.com"));

        // Restore from dbv1, alice persisted.
        let vs3 = valueset::from_db_valueset_v2(vs.to_db_valueset_v2())
            .expect("Failed to construct vs2 from dbvalue");
        assert!(&vs == &vs3);
        assert!(vs3.len() == 2);
        assert!(vs3
            .as_emailaddress_set()
            .map(|(_p, s)| s)
            .unwrap()
            .contains("alice@example.com"));
        assert!(vs3
            .as_emailaddress_set()
            .map(|(_p, s)| s)
            .unwrap()
            .contains("claire@example.com"));

        // If we clear, no primary.
        vs.clear();
        assert!(vs.len() == 0);
        assert!(vs.to_email_address_primary_str().is_none());
    }
}
