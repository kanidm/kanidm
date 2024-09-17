//! These represent Kanidm's view of SCIM resources that a client will serialise
//! for transmission, and the server will deserialise to process them. In reverse
//! Kanidm will send responses that a client can then process and use.
//!
//! A challenge of this is that it creates an asymmetry between the client and server
//! as SCIM contains very few strong types. Without awareness of what the client
//! or server intended it's not possible to directly deserialise into a rust
//! strong type on the receiver. To resolve this, this library divides the elements
//! into multiple parts.
//!
//! The [scim_proto] library, which is generic over all scim implementations.
//!
//! The client module, which describes how a client should transmit entries, and
//! how it should parse them when it recieves them.
//!
//! The server module, which describes how a server should transmit entries and
//! how it should recieve them.

use crate::attribute::Attribute;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use utoipa::ToSchema;

pub use self::synch::*;
pub use scim_proto::prelude::*;

mod client;
pub mod server;
mod synch;

/// A generic ScimEntry. This retains attribute
/// values in a generic state awaiting processing by schema aware transforms
/// either by the server or the client.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ScimEntryGeneric {
    #[serde(flatten)]
    pub header: ScimEntryHeader,
    #[serde(flatten)]
    pub attrs: BTreeMap<Attribute, JsonValue>,
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_scim_rfc_to_generic() {
        // Assert that we can transition from the rfc generic entries to the
        // kanidm types.
    }

    #[test]
    fn test_scim_kani_to_generic() {
        // Assert that a kanidm strong entry can convert to generic.
    }

    #[test]
    fn test_scim_kani_to_rfc() {
        // Assert that a kanidm strong entry can convert to rfc.
    }

    #[test]
    fn test_scim_sync_kani_to_rfc() {
        use super::*;

        // Group
        let group_uuid = uuid::uuid!("2d0a9e7c-cc08-4ca2-8d7f-114f9abcfc8a");

        let group = ScimSyncGroup::builder("testgroup".to_string(), group_uuid)
            .set_description(Some("test desc".to_string()))
            .set_gidnumber(Some(12345))
            .set_members(vec!["member_a".to_string(), "member_a".to_string()].into_iter())
            .set_external_id(Some("cn=testgroup".to_string()))
            .build();

        let entry: Result<ScimEntry, _> = group.try_into();

        assert!(entry.is_ok());

        // User
        let user_uuid = uuid::uuid!("cb3de098-33fd-4565-9d80-4f7ed6a664e9");

        let user_sshkey = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBENubZikrb8hu+HeVRdZ0pp/VAk2qv4JDbuJhvD0yNdWDL2e3cBbERiDeNPkWx58Q4rVnxkbV1fa8E2waRtT91wAAAAEc3NoOg== testuser@fidokey";

        let person =
            ScimSyncPerson::builder(user_uuid, "testuser".to_string(), "Test User".to_string())
                .set_password_import(Some("new_password".to_string()))
                .set_unix_password_import(Some("new_password".to_string()))
                .set_totp_import(vec![ScimTotp {
                    external_id: "Totp".to_string(),
                    secret: "abcd".to_string(),
                    algo: "SHA3".to_string(),
                    step: 60,
                    digits: 8,
                }])
                .set_mail(vec![MultiValueAttr {
                    primary: Some(true),
                    value: "testuser@example.com".to_string(),
                    ..Default::default()
                }])
                .set_ssh_publickey(vec![ScimSshPubKey {
                    label: "Key McKeyface".to_string(),
                    value: user_sshkey.to_string(),
                }])
                .set_login_shell(Some("/bin/false".to_string()))
                .set_account_valid_from(Some("2023-11-28T04:57:55Z".to_string()))
                .set_account_expire(Some("2023-11-28T04:57:55Z".to_string()))
                .set_gidnumber(Some(54321))
                .set_external_id(Some("cn=testuser".to_string()))
                .build();

        let entry: Result<ScimEntry, _> = person.try_into();

        assert!(entry.is_ok());
    }
}
