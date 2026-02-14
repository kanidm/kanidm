use crate::prelude::*;
use crate::schema::{SchemaAttribute, SchemaTransaction};
use crate::server::assert::{AssertEvent, AssertOnce, EntryAssertion};
use crate::server::batch_modify::{BatchModifyEvent, ModSetValid};
use crate::server::ValueSetResolveStatus;
use crate::valueset::*;
use crypto_glue::s256::Sha256Output;
use kanidm_proto::scim_v1::client::{
    ScimEntryAssertion, ScimEntryPostGeneric, ScimEntryPutGeneric,
};
use kanidm_proto::scim_v1::JsonValue;
use std::collections::{
    // BTreeSet,
    BTreeMap,
};

#[derive(Debug)]
pub struct ScimEntryPutEvent {
    /// The identity performing the change.
    pub(crate) ident: Identity,

    // future - etags to detect version changes.
    /// The target entry that will be changed
    pub(crate) target: Uuid,
    /// Update an attribute to contain the following value state.
    /// If the attribute is None, it is removed.
    pub(crate) attrs: BTreeMap<Attribute, Option<ValueSet>>,

    /// If an effective access check should be carried out post modification
    /// of the entries
    pub(crate) effective_access_check: bool,
}

impl ScimEntryPutEvent {
    pub fn try_from(
        ident: Identity,
        entry: ScimEntryPutGeneric,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let target = entry.id;

        let attrs = entry
            .attrs
            .into_iter()
            .map(|(attr, json_value)| {
                qs.resolve_scim_json_put(&attr, json_value)
                    .map(|kani_value| (attr, kani_value))
            })
            .collect::<Result<_, _>>()?;

        let query = entry.query;

        Ok(ScimEntryPutEvent {
            ident,
            target,
            attrs,
            effective_access_check: query.ext_access_check,
        })
    }
}

#[derive(Debug)]
pub struct ScimCreateEvent {
    pub(crate) ident: Identity,
    pub(crate) entry: EntryInitNew,
}

impl ScimCreateEvent {
    pub fn try_from(
        ident: Identity,
        classes: &[EntryClass],
        entry: ScimEntryPostGeneric,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let mut entry = entry
            .attrs
            .into_iter()
            .map(|(attr, json_value)| {
                qs.resolve_scim_json_post(&attr, json_value)
                    .map(|kani_value| (attr, kani_value))
            })
            .collect::<Result<EntryInitNew, _>>()?;

        if !classes.is_empty() {
            let classes = ValueSetIutf8::from_iter(classes.iter().map(|cls| cls.as_ref()))
                .ok_or(OperationError::SC0027ClassSetInvalid)?;

            entry.set_ava_set(&Attribute::Class, classes);
        }

        Ok(ScimCreateEvent { ident, entry })
    }
}

#[derive(Debug)]
pub struct ScimDeleteEvent {
    /// The identity performing the change.
    pub(crate) ident: Identity,

    // future - etags to detect version changes.
    /// The target entry that will be changed
    pub(crate) target: Uuid,

    /// The class of the target entry.
    pub(crate) class: EntryClass,
}

impl ScimDeleteEvent {
    pub fn new(ident: Identity, target: Uuid, class: EntryClass) -> Self {
        ScimDeleteEvent {
            ident,
            target,
            class,
        }
    }
}

#[derive(Debug)]
pub struct ScimAssertEvent {
    /// The identity performing the change.
    pub(crate) ident: Identity,

    /// The set of assertions to be performed. These are applied in order.
    pub(crate) asserts: Vec<ScimEntryAssertion>,

    /// Tracking information about the assertion.
    pub id: Uuid,

    /// The nonce/checksum of the operation if we want to do this "at most once".
    pub nonce: Option<Sha256Output>,
}

impl ScimAssertEvent {
    pub fn new_internal(
        asserts: Vec<ScimEntryAssertion>,
        id: Uuid,
        nonce: Option<Sha256Output>,
    ) -> Self {
        ScimAssertEvent {
            ident: Identity::from_internal(),
            asserts,
            id,
            nonce,
        }
    }
}

impl QueryServerWriteTransaction<'_> {
    /// SCIM PUT is the handler where a single entry is updated. In a SCIM PUT request
    /// the request defines the state of an attribute in entirety for the update. This
    /// means if the caller wants to add one email address, they must PUT all existing
    /// addresses in addition to the new one.
    pub fn scim_put(
        &mut self,
        scim_entry_put: ScimEntryPutEvent,
    ) -> Result<ScimEntryKanidm, OperationError> {
        let ScimEntryPutEvent {
            ident,
            target,
            attrs,
            effective_access_check,
        } = scim_entry_put;

        // This function transforms the put event into a modify event.
        let mods_invalid: ModifyList<ModifyInvalid> = attrs.into();

        let mods_valid = mods_invalid
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let mut modset = ModSetValid::default();

        modset.insert(target, mods_valid);

        let modify_event = BatchModifyEvent {
            ident: ident.clone(),
            modset,
        };

        // dispatch to batch modify
        self.batch_modify(&modify_event)?;

        // Now get the entry. We handle a lot of the errors here nicely,
        // but if we got to this point, they really can't happen.
        let filter_intent = filter!(f_and!([f_eq(Attribute::Uuid, PartialValue::Uuid(target))]));

        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let f_valid = f_intent_valid.clone().into_ignore_hidden();

        let se = SearchEvent {
            ident,
            filter: f_valid,
            filter_orig: f_intent_valid,
            // Return all attributes, even ones we didn't affect
            attrs: None,
            effective_access_check,
        };

        let mut vs = self.search_ext(&se)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => entry.to_scim_kanidm(self),
            _ => {
                if vs.is_empty() {
                    Err(OperationError::NoMatchingEntries)
                } else {
                    // Multiple entries matched, should not be possible!
                    Err(OperationError::UniqueConstraintViolation)
                }
            }
        }
    }

    pub fn scim_create(
        &mut self,
        scim_create: ScimCreateEvent,
    ) -> Result<ScimEntryKanidm, OperationError> {
        let ScimCreateEvent { ident, entry } = scim_create;

        let create_event = CreateEvent {
            ident,
            entries: vec![entry],
            return_created_uuids: true,
        };

        let changed_uuids = self.create(&create_event)?;

        let mut changed_uuids = changed_uuids.ok_or(OperationError::SC0028CreatedUuidsInvalid)?;

        let target = if let Some(target) = changed_uuids.pop() {
            if !changed_uuids.is_empty() {
                // Too many results!
                return Err(OperationError::UniqueConstraintViolation);
            }

            target
        } else {
            // No results!
            return Err(OperationError::NoMatchingEntries);
        };

        // Now get the entry. We handle a lot of the errors here nicely,
        // but if we got to this point, they really can't happen.
        let filter_intent = filter!(f_and!([f_eq(Attribute::Uuid, PartialValue::Uuid(target))]));

        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let f_valid = f_intent_valid.clone().into_ignore_hidden();

        let se = SearchEvent {
            ident: create_event.ident,
            filter: f_valid,
            filter_orig: f_intent_valid,
            // Return all attributes
            attrs: None,
            effective_access_check: false,
        };

        let mut vs = self.search_ext(&se)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => entry.to_scim_kanidm(self),
            _ => {
                if vs.is_empty() {
                    Err(OperationError::NoMatchingEntries)
                } else {
                    // Multiple entries matched, should not be possible!
                    Err(OperationError::UniqueConstraintViolation)
                }
            }
        }
    }

    pub fn scim_delete(&mut self, scim_delete: ScimDeleteEvent) -> Result<(), OperationError> {
        let ScimDeleteEvent {
            ident,
            target,
            class,
        } = scim_delete;

        let filter_intent = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target)));
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let filter = filter!(f_and!([
            f_eq(Attribute::Uuid, PartialValue::Uuid(target)),
            f_eq(Attribute::Class, class.into())
        ]));
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let de = DeleteEvent {
            ident,
            filter: f_valid,
            filter_orig: f_intent_valid,
        };

        self.delete(&de)
    }

    pub fn scim_assert(&mut self, scim_assert: ScimAssertEvent) -> Result<(), OperationError> {
        let ScimAssertEvent {
            ident,
            asserts,
            id,
            nonce,
        } = scim_assert;

        let once = match nonce {
            None => AssertOnce::No,
            Some(nonce) => AssertOnce::Yes { id, nonce },
        };

        // Before we can transform this, we have to resolve links that *may* exist
        // within this assertion.
        self.txn_name_to_uuid().extend(asserts.iter().filter_map(
            |scim_assert| match scim_assert {
                ScimEntryAssertion::Present { id, attrs } => {
                    attrs
                        .get(&Attribute::Name)
                        .and_then(|value| match value {
                            // If the name is present, and a valid string.
                            Some(JsonValue::String(name)) => Some(name.clone()),
                            _ => None,
                        })
                        .map(|name| (name, *id))
                }
                ScimEntryAssertion::Absent { .. } => None,
            },
        ));

        // Transform from SCIM to Kanidm Internal representations.
        let asserts = asserts
            .into_iter()
            .map(|scim_assert| match scim_assert {
                ScimEntryAssertion::Present { id, attrs } => {
                    let attrs = attrs
                        .into_iter()
                        .map(|(attr, json_value)| {
                            self.resolve_scim_json_put(&attr, json_value)
                                .map(|kani_value| (attr, kani_value))
                        })
                        .collect::<Result<_, _>>()?;

                    Ok(EntryAssertion::Present { target: id, attrs })
                }
                ScimEntryAssertion::Absent { id } => Ok(EntryAssertion::Absent { target: id }),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let assert_event = AssertEvent {
            ident,
            asserts,
            once,
        };

        self.assert(assert_event)
    }

    pub(crate) fn resolve_scim_json_put(
        &mut self,
        attr: &Attribute,
        value: Option<JsonValue>,
    ) -> Result<Option<ValueSet>, OperationError> {
        let schema = self.get_schema();
        // Lookup the attr
        let Some(schema_a) = schema.get_attributes().get(attr) else {
            // No attribute of this name exists - fail fast, there is no point to
            // proceed, as nothing can be satisfied.
            return Err(OperationError::InvalidAttributeName(attr.to_string()));
        };

        let Some(value) = value else {
            // It's a none so the value needs to be unset, and the attr DOES exist in
            // schema.
            return Ok(None);
        };

        self.resolve_scim_json(schema_a, value).map(Some)
    }

    pub(crate) fn resolve_scim_json_post(
        &mut self,
        attr: &Attribute,
        value: JsonValue,
    ) -> Result<ValueSet, OperationError> {
        let schema = self.get_schema();
        // Lookup the attr
        let Some(schema_a) = schema.get_attributes().get(attr) else {
            // No attribute of this name exists - fail fast, there is no point to
            // proceed, as nothing can be satisfied.
            return Err(OperationError::InvalidAttributeName(attr.to_string()));
        };

        self.resolve_scim_json(schema_a, value)
    }

    fn resolve_scim_json(
        &mut self,
        schema_a: &SchemaAttribute,
        value: JsonValue,
    ) -> Result<ValueSet, OperationError> {
        let resolve_status = match schema_a.syntax {
            SyntaxType::Utf8String => ValueSetUtf8::from_scim_json_put(value),
            SyntaxType::Utf8StringInsensitive => ValueSetIutf8::from_scim_json_put(value),
            SyntaxType::Uuid => ValueSetUuid::from_scim_json_put(value),
            SyntaxType::Boolean => ValueSetBool::from_scim_json_put(value),
            SyntaxType::SyntaxId => ValueSetSyntax::from_scim_json_put(value),
            SyntaxType::IndexId => ValueSetIndex::from_scim_json_put(value),
            SyntaxType::ReferenceUuid => ValueSetRefer::from_scim_json_put(value),
            SyntaxType::Utf8StringIname => ValueSetIname::from_scim_json_put(value),
            SyntaxType::NsUniqueId => ValueSetNsUniqueId::from_scim_json_put(value),
            SyntaxType::DateTime => ValueSetDateTime::from_scim_json_put(value),
            SyntaxType::EmailAddress => ValueSetEmailAddress::from_scim_json_put(value),
            SyntaxType::Url => ValueSetUrl::from_scim_json_put(value),
            SyntaxType::OauthScope => ValueSetOauthScope::from_scim_json_put(value),
            SyntaxType::OauthScopeMap => ValueSetOauthScopeMap::from_scim_json_put(value),
            SyntaxType::OauthClaimMap => ValueSetOauthClaimMap::from_scim_json_put(value),
            SyntaxType::UiHint => ValueSetUiHint::from_scim_json_put(value),
            SyntaxType::CredentialType => ValueSetCredentialType::from_scim_json_put(value),
            SyntaxType::Certificate => ValueSetCertificate::from_scim_json_put(value),
            SyntaxType::SshKey => ValueSetSshKey::from_scim_json_put(value),
            SyntaxType::Uint32 => ValueSetUint32::from_scim_json_put(value),
            SyntaxType::Int64 => ValueSetInt64::from_scim_json_put(value),
            SyntaxType::Uint64 => ValueSetUint64::from_scim_json_put(value),
            SyntaxType::Sha256 => ValueSetSha256::from_scim_json_put(value),

            // Not Yet ... if ever
            // SyntaxType::JsonFilter => ValueSetJsonFilter::from_scim_json_put(value),
            SyntaxType::JsonFilter => Err(OperationError::InvalidAttribute(
                "Json Filters are not able to be set.".to_string(),
            )),
            // Not Yet ... if ever.
            SyntaxType::Json => Err(OperationError::InvalidAttribute(
                "Json values are not able to be set.".to_string(),
            )),
            SyntaxType::Message => Err(OperationError::InvalidAttribute(
                "Message values are not able to be set.".to_string(),
            )),
            // Can't be set currently as these are only internally generated for key-id's
            // SyntaxType::HexString => ValueSetHexString::from_scim_json_put(value),
            SyntaxType::HexString => Err(OperationError::InvalidAttribute(
                "Hex strings are not able to be set.".to_string(),
            )),

            // Can't be set until we have better error handling in the set paths
            // SyntaxType::Image => ValueSetImage::from_scim_json_put(value),
            SyntaxType::Image => Err(OperationError::InvalidAttribute(
                "Images are not able to be set.".to_string(),
            )),

            // Can't be set yet, mostly as I'm lazy
            // SyntaxType::WebauthnAttestationCaList => {
            //    ValueSetWebauthnAttestationCaList::from_scim_json_put(value)
            // }
            SyntaxType::WebauthnAttestationCaList => Err(OperationError::InvalidAttribute(
                "Webauthn Attestation Ca Lists are not able to be set.".to_string(),
            )),

            // Syntax types that can not be submitted
            SyntaxType::Credential => Err(OperationError::InvalidAttribute(
                "Credentials are not able to be set.".to_string(),
            )),
            SyntaxType::SecretUtf8String => Err(OperationError::InvalidAttribute(
                "Secrets are not able to be set.".to_string(),
            )),
            SyntaxType::SecurityPrincipalName => Err(OperationError::InvalidAttribute(
                "SPNs are not able to be set.".to_string(),
            )),
            SyntaxType::Cid => Err(OperationError::InvalidAttribute(
                "CIDs are not able to be set.".to_string(),
            )),
            SyntaxType::PrivateBinary => Err(OperationError::InvalidAttribute(
                "Private Binaries are not able to be set.".to_string(),
            )),
            SyntaxType::IntentToken => Err(OperationError::InvalidAttribute(
                "Intent Tokens are not able to be set.".to_string(),
            )),
            SyntaxType::Passkey => Err(OperationError::InvalidAttribute(
                "Passkeys are not able to be set.".to_string(),
            )),
            SyntaxType::AttestedPasskey => Err(OperationError::InvalidAttribute(
                "Attested Passkeys are not able to be set.".to_string(),
            )),
            SyntaxType::Session => Err(OperationError::InvalidAttribute(
                "Sessions are not able to be set.".to_string(),
            )),
            SyntaxType::JwsKeyEs256 => Err(OperationError::InvalidAttribute(
                "Jws ES256 Private Keys are not able to be set.".to_string(),
            )),
            SyntaxType::JwsKeyRs256 => Err(OperationError::InvalidAttribute(
                "Jws RS256 Private Keys are not able to be set.".to_string(),
            )),
            SyntaxType::Oauth2Session => Err(OperationError::InvalidAttribute(
                "Sessions are not able to be set.".to_string(),
            )),
            SyntaxType::TotpSecret => Err(OperationError::InvalidAttribute(
                "TOTP Secrets are not able to be set.".to_string(),
            )),
            SyntaxType::ApiToken => Err(OperationError::InvalidAttribute(
                "API Tokens are not able to be set.".to_string(),
            )),
            SyntaxType::AuditLogString => Err(OperationError::InvalidAttribute(
                "Audit Strings are not able to be set.".to_string(),
            )),
            SyntaxType::EcKeyPrivate => Err(OperationError::InvalidAttribute(
                "EC Private Keys are not able to be set.".to_string(),
            )),
            SyntaxType::KeyInternal => Err(OperationError::InvalidAttribute(
                "Key Internal Structures are not able to be set.".to_string(),
            )),
            SyntaxType::ApplicationPassword => Err(OperationError::InvalidAttribute(
                "Application Passwords are not able to be set.".to_string(),
            )),
        }?;

        match resolve_status {
            ValueSetResolveStatus::Resolved(vs) => Ok(vs),
            ValueSetResolveStatus::NeedsResolution(vs_inter) => {
                self.resolve_valueset_intermediate(vs_inter)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ScimAssertEvent, ScimEntryPutEvent};
    use crate::prelude::*;
    use kanidm_proto::scim_v1::client::{
        ScimEntryAssertion, ScimEntryPutKanidm, ScimReference as ScimClientReference,
    };
    use kanidm_proto::scim_v1::server::ScimReference;
    use kanidm_proto::scim_v1::ScimMail;
    use std::collections::BTreeMap;

    #[qs_test]
    async fn scim_put_basic(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let idm_admin_entry = server_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();

        let idm_admin_ident = Identity::from_impersonate_entry_readwrite(idm_admin_entry);

        // Make an entry.
        let group_uuid = Uuid::new_v4();

        // Add members to our groups to test reference handling in scim
        let extra1_uuid = Uuid::new_v4();
        let extra2_uuid = Uuid::new_v4();
        let extra3_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(group_uuid))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("extra_1")),
            (Attribute::Uuid, Value::Uuid(extra1_uuid))
        );

        let e3 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("extra_2")),
            (Attribute::Uuid, Value::Uuid(extra2_uuid))
        );

        let e4 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("extra_3")),
            (Attribute::Uuid, Value::Uuid(extra3_uuid))
        );

        assert!(server_txn.internal_create(vec![e1, e2, e3, e4]).is_ok());

        // Set attrs
        let test_mails = vec![
            ScimMail {
                primary: true,
                value: "test@test.test".to_string(),
            },
            ScimMail {
                primary: false,
                value: "test2@test.test".to_string(),
            },
        ];
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [
                (Attribute::Description, Some("Group Description".into())),
                (
                    Attribute::Mail,
                    Some(ScimValueKanidm::Mail(test_mails.clone())),
                ),
            ]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let desc = updated_entry.attrs.get(&Attribute::Description).unwrap();
        let mails = updated_entry.attrs.get(&Attribute::Mail).unwrap();

        match desc {
            ScimValueKanidm::String(gdesc) if gdesc == "Group Description" => {}
            _ => unreachable!("Expected a string"),
        };

        let ScimValueKanidm::Mail(mails) = mails else {
            unreachable!("Expected an email")
        };

        // asserts emails ⊂ test_mails
        assert!(mails.iter().all(|mail| test_mails.contains(mail)));

        // null removes attr
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(Attribute::Description, None)].into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        assert!(!updated_entry.attrs.contains_key(&Attribute::Description));

        // set one
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::EntryReferences(vec![ScimReference {
                    uuid: extra1_uuid,
                    // Doesn't matter what this is, because there is a UUID, it's ignored
                    value: String::default(),
                }])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        trace!(?members);

        match members {
            ScimValueKanidm::EntryReferences(member_set) if member_set.len() == 1 => {
                assert!(member_set.contains(&ScimReference {
                    uuid: extra1_uuid,
                    value: "extra_1@example.com".to_string(),
                }));
            }
            _ => unreachable!("Expected 1 member"),
        };

        // set many
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::EntryReferences(vec![
                    ScimReference {
                        uuid: extra1_uuid,
                        value: String::default(),
                    },
                    ScimReference {
                        uuid: extra2_uuid,
                        value: String::default(),
                    },
                    ScimReference {
                        uuid: extra3_uuid,
                        value: String::default(),
                    },
                ])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        trace!(?members);

        match members {
            ScimValueKanidm::EntryReferences(member_set) if member_set.len() == 3 => {
                assert!(member_set.contains(&ScimReference {
                    uuid: extra1_uuid,
                    value: "extra_1@example.com".to_string(),
                }));
                assert!(member_set.contains(&ScimReference {
                    uuid: extra2_uuid,
                    value: "extra_2@example.com".to_string(),
                }));
                assert!(member_set.contains(&ScimReference {
                    uuid: extra3_uuid,
                    value: "extra_3@example.com".to_string(),
                }));
            }
            _ => unreachable!("Expected 3 members"),
        };

        // set many with a removal
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(
                Attribute::Member,
                Some(ScimValueKanidm::EntryReferences(vec![
                    ScimReference {
                        uuid: extra1_uuid,
                        value: String::default(),
                    },
                    ScimReference {
                        uuid: extra3_uuid,
                        value: String::default(),
                    },
                ])),
            )]
            .into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        let members = updated_entry.attrs.get(&Attribute::Member).unwrap();

        trace!(?members);

        match members {
            ScimValueKanidm::EntryReferences(member_set) if member_set.len() == 2 => {
                assert!(member_set.contains(&ScimReference {
                    uuid: extra1_uuid,
                    value: "extra_1@example.com".to_string(),
                }));
                assert!(member_set.contains(&ScimReference {
                    uuid: extra3_uuid,
                    value: "extra_3@example.com".to_string(),
                }));
                // Member 2 is gone
                assert!(!member_set.contains(&ScimReference {
                    uuid: extra2_uuid,
                    value: "extra_2@example.com".to_string(),
                }));
            }
            _ => unreachable!("Expected 2 members"),
        };

        // empty set removes attr
        let put = ScimEntryPutKanidm {
            id: group_uuid,
            attrs: [(Attribute::Member, None)].into(),
        };

        let put_generic = put.try_into().unwrap();
        let put_event =
            ScimEntryPutEvent::try_from(idm_admin_ident.clone(), put_generic, &mut server_txn)
                .expect("Failed to resolve data type");

        let updated_entry = server_txn.scim_put(put_event).expect("Failed to put");
        assert!(!updated_entry.attrs.contains_key(&Attribute::Member));
    }

    #[qs_test]
    async fn scim_assert_basic(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let ident = Identity::from_internal();

        let uuid_group_1 = Uuid::new_v4();
        let uuid_group_2 = Uuid::new_v4();

        let asserts = vec![
            ScimEntryAssertion::Present {
                id: uuid_group_1,
                attrs: BTreeMap::from([
                    (Attribute::Name, Some(JsonValue::String("group_1".into()))),
                    (
                        Attribute::Class,
                        Some(serde_json::to_value(vec!["group"]).unwrap()),
                    ),
                    (
                        Attribute::Member,
                        Some(serde_json::to_value(ScimClientReference::from("group_2")).unwrap()),
                    ),
                ]),
            },
            ScimEntryAssertion::Present {
                id: uuid_group_2,
                attrs: BTreeMap::from([
                    (Attribute::Name, Some(JsonValue::String("group_2".into()))),
                    (
                        Attribute::Class,
                        Some(serde_json::to_value(vec!["group"]).unwrap()),
                    ),
                    (
                        Attribute::Member,
                        Some(serde_json::to_value(ScimClientReference::from("group_1")).unwrap()),
                    ),
                ]),
            },
        ];

        let scim_assert = ScimAssertEvent {
            ident,
            asserts,
            id: Uuid::new_v4(),
            nonce: None,
        };

        server_txn.scim_assert(scim_assert).expect("Must not fail!");
    }
}
