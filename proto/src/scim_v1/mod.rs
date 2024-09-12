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
}
