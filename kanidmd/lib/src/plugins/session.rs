//! This plugin maintains consistency of authenticated sessions on accounts.
//!
//! An example of this is that oauth2 sessions are child of user auth sessions,
//! such than when the user auth session is terminated, then the corresponding
//! oauth2 session should also be terminated.
//!
//! This plugin is also responsible for invaliding old sessions that are past
//! their expiry.

use crate::event::ModifyEvent;
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct SessionConsistency {}

impl Plugin for SessionConsistency {
    fn id() -> &'static str {
        "plugin_session_consistency"
    }

    #[instrument(level = "debug", name = "session_consistency", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        /*
        cand.iter_mut().try_for_each(|_e| {
        });
        */

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // use kanidm_proto::v1::PluginError;
    // use crate::prelude::*;

    #[test]
    fn test_session_consistency_basic() {}
}
