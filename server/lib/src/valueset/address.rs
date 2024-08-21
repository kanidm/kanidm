use std::collections::BTreeSet;

use smolset::SmolSet;

use crate::be::dbvalue::DbValueAddressV1;
use crate::prelude::*;
use crate::repl::proto::{ReplAddressV1, ReplAttrV1};
use crate::schema::SchemaAttribute;
use crate::utils::trigraph_iter;
use crate::value::{Address, VALIDATE_EMAIL_RE};
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

    pub fn from_repl_v1(data: &[ReplAddressV1]) -> Result<ValueSet, OperationError> {
        let set = data
            .iter()
            .cloned()
            .map(
                |ReplAddressV1 {
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
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

    fn to_scim_value(&self) -> ScimValue {
        ScimValue::MultiComplex(
            self.set
                .iter()
                .map(|a| {
                    let mut complex_attr = ScimComplexAttr::default();

                    complex_attr.insert("formatted".to_string(), a.formatted.clone().into());
                    complex_attr
                        .insert("stretAddress".to_string(), a.street_address.clone().into());
                    complex_attr.insert("locality".to_string(), a.locality.clone().into());
                    complex_attr.insert("region".to_string(), a.region.clone().into());
                    complex_attr.insert("postalCode".to_string(), a.postal_code.clone().into());
                    complex_attr.insert("country".to_string(), a.country.clone().into());

                    complex_attr
                })
                .collect(),
        )
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

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::Address {
            set: self
                .set
                .iter()
                .map(|a| ReplAddressV1 {
                    formatted: a.formatted.clone(),
                    street_address: a.street_address.clone(),
                    locality: a.locality.clone(),
                    region: a.region.clone(),
                    postal_code: a.postal_code.clone(),
                    country: a.country.clone(),
                })
                .collect(),
        }
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
            self.primary.clone_from(&a);
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

    pub fn from_repl_v1(primary: &str, data: &[String]) -> Result<ValueSet, OperationError> {
        let set: BTreeSet<_> = data.iter().cloned().collect();

        if set.contains(primary) {
            Ok(Box::new(ValueSetEmailAddress {
                primary: primary.to_string(),
                set,
            }))
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
                    self.primary.clone_from(&a);
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

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::EmailAddress(a) => {
                let r = self.set.remove(a);
                if &self.primary == a {
                    // if we can, inject another former address into primary.
                    if let Some(n) = self.set.iter().take(1).next().cloned() {
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

    fn substring(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::EmailAddress(s2) => {
                // We lowercase as LDAP and similar expect case insensitive searches here.
                let s2_lower = s2.to_lowercase();
                self.set
                    .iter()
                    .any(|s1| s1.to_lowercase().contains(&s2_lower))
            }
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn startswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::EmailAddress(s2) => {
                // We lowercase as LDAP and similar expect case insensitive searches here.
                let s2_lower = s2.to_lowercase();
                self.set
                    .iter()
                    .any(|s1| s1.to_lowercase().starts_with(&s2_lower))
            }
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn endswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::EmailAddress(s2) => {
                // We lowercase as LDAP and similar expect case insensitive searches here.
                let s2_lower = s2.to_lowercase();
                self.set
                    .iter()
                    .any(|s1| s1.to_lowercase().ends_with(&s2_lower))
            }
            _ => {
                debug_assert!(false);
                false
            }
        }
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

    fn generate_idx_sub_keys(&self) -> Vec<String> {
        let lower: Vec<_> = self.set.iter().map(|s| s.to_lowercase()).collect();
        let mut trigraphs: Vec<_> = lower.iter().flat_map(|v| trigraph_iter(v)).collect();

        trigraphs.sort_unstable();
        trigraphs.dedup();

        trigraphs.into_iter().map(String::from).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::EmailAddress
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.contains(&self.primary)
            && self
                .set
                .iter()
                .all(|mail| VALIDATE_EMAIL_RE.is_match(mail.as_str()))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        if self.primary.is_empty() {
            Box::new(self.set.iter().cloned())
        } else {
            Box::new(
                std::iter::once(self.primary.clone()).chain(
                    self.set
                        .iter()
                        .filter(|mail| **mail != self.primary)
                        .cloned(),
                ),
            )
        }
    }

    fn to_scim_value(&self) -> ScimValue {
        ScimValue::MultiComplex(
            std::iter::once({
                let mut complex_attr = ScimComplexAttr::default();

                complex_attr.insert("value".to_string(), self.primary.clone().into());
                complex_attr.insert("primary".to_string(), true.into());

                complex_attr
            })
            .chain(self.set.iter().filter_map(|mail| {
                if **mail == self.primary {
                    None
                } else {
                    let mut complex_attr = ScimComplexAttr::default();

                    complex_attr.insert("value".to_string(), mail.clone().into());
                    complex_attr.insert("primary".to_string(), false.into());
                    Some(complex_attr)
                }
            }))
            .collect(),
        )
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::EmailAddress(self.primary.clone(), self.set.iter().cloned().collect())
    }

    fn to_repl_v1(&self) -> ReplAttrV1 {
        ReplAttrV1::EmailAddress {
            primary: self.primary.clone(),
            set: self.set.iter().cloned().collect(),
        }
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
    use super::{ValueSetAddress, ValueSetEmailAddress};
    use crate::prelude::ScimValue;
    use crate::repl::cid::Cid;
    use crate::value::{Address, PartialValue, Value};
    use crate::valueset::{self, ValueSet};

    #[test]
    fn test_valueset_emailaddress() {
        // Can be created
        //
        let mut vs: ValueSet = ValueSetEmailAddress::new("claire@example.com".to_string());

        assert_eq!(vs.len(), 1);
        assert_eq!(
            vs.to_email_address_primary_str(),
            Some("claire@example.com")
        );

        // Add another, still not primary.
        assert!(
            vs.insert_checked(
                Value::new_email_address_s("alice@example.com").expect("Invalid Email")
            ) == Ok(true)
        );

        assert_eq!(vs.len(), 2);
        assert_eq!(
            vs.to_email_address_primary_str(),
            Some("claire@example.com")
        );

        // Update primary
        assert!(
            vs.insert_checked(
                Value::new_email_address_primary_s("primary@example.com").expect("Invalid Email")
            ) == Ok(true)
        );
        assert_eq!(
            vs.to_email_address_primary_str(),
            Some("primary@example.com")
        );

        // Restore from dbv1, ensure correct primary
        let vs2 = valueset::from_db_valueset_v2(vs.to_db_valueset_v2())
            .expect("Failed to construct vs2 from dbvalue");

        assert_eq!(&vs, &vs2);
        assert_eq!(
            vs.to_email_address_primary_str(),
            vs2.to_email_address_primary_str()
        );

        // Remove primary, assert it's gone and that the "first" address is assigned.
        assert!(vs.remove(
            &PartialValue::new_email_address_s("primary@example.com"),
            &Cid::new_zero()
        ));
        assert_eq!(vs.len(), 2);
        assert_eq!(vs.to_email_address_primary_str(), Some("alice@example.com"));

        // Restore from dbv1, alice persisted.
        let vs3 = valueset::from_db_valueset_v2(vs.to_db_valueset_v2())
            .expect("Failed to construct vs2 from dbvalue");
        assert_eq!(&vs, &vs3);
        assert_eq!(vs3.len(), 2);
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
        assert_eq!(vs.len(), 0);
        assert!(vs.to_email_address_primary_str().is_none());
    }

    #[test]
    fn test_scim_emailaddress() {
        let mut vs: ValueSet = ValueSetEmailAddress::new("claire@example.com".to_string());
        // Add another, still not primary.
        assert!(
            vs.insert_checked(
                Value::new_email_address_s("alice@example.com").expect("Invalid Email")
            ) == Ok(true)
        );

        let scim_value = vs.to_scim_value();

        let expect: ScimValue = serde_json::from_str(
            r#"[
          {
            "primary": true,
            "value": "claire@example.com"
          },
          {
            "primary": false,
            "value": "alice@example.com"
          }
        ]"#,
        )
        .unwrap();

        assert_eq!(scim_value, expect);
    }

    #[test]
    fn test_scim_address() {
        let vs: ValueSet = ValueSetAddress::new(Address {
            formatted: "1 No Where Lane, Doesn't Exist, Brisbane, 0420, Australia".to_string(),
            street_address: "1 No Where Lane".to_string(),
            locality: "Doesn't Exist".to_string(),
            region: "Brisbane".to_string(),
            postal_code: "0420".to_string(),
            country: "Australia".to_string(),
        });

        let scim_value = vs.to_scim_value();

        let expect: ScimValue = serde_json::from_str(
            r#"[
          {
            "country": "Australia",
            "formatted": "1 No Where Lane, Doesn't Exist, Brisbane, 0420, Australia",
            "locality": "Doesn't Exist",
            "postalCode": "0420",
            "region": "Brisbane",
            "stretAddress": "1 No Where Lane"
          }
        ]"#,
        )
        .unwrap();

        assert_eq!(scim_value, expect);

        // let strout = serde_json::to_string_pretty(&scim_value).unwrap();
        // eprintln!("{}", strout);
    }
}
