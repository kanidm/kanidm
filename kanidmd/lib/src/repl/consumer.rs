use super::proto::ReplRefreshContext;
use crate::prelude::*;

impl<'a> QueryServerReadTransaction<'a> {
    // Get the current state of "where we are up to"
    //
    // There are two approaches we can use here. We can either store a cookie
    // related to the supplier we are fetching from, or we can use our RUV state.
    //
    // Initially I'm using RUV state, because it lets us select exactly what has
    // changed, where the cookie approach is more coarse grained. The cookie also
    // requires some more knowledge about what supplier we are communicating too
    // where the RUV approach doesn't since the supplier calcs the diff.

    #[instrument(level = "debug", skip_all)]
    pub fn consumer_get_state(&mut self) -> Result<(), OperationError> {
        Ok(())
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    // Apply the state changes if they are valid.

    #[instrument(level = "debug", skip_all)]
    pub fn consumer_apply_changes(&mut self) -> Result<(), OperationError> {
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn consumer_apply_refresh(
        &mut self,
        ctx: &ReplRefreshContext,
    ) -> Result<(), OperationError> {
        // Can we apply the domain version validly?
        // if domain_version >= min_support ...

        if ctx.domain_version < DOMAIN_MIN_LEVEL {
            error!("Unable to proceed with consumer refresh - incoming domain level is lower than our minimum supported level. {} < {}", ctx.domain_version, DOMAIN_MIN_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else if ctx.domain_version > DOMAIN_MAX_LEVEL {
            error!("Unable to proceed with consumer refresh - incoming domain level is greater than our maximum supported level. {} > {}", ctx.domain_version, DOMAIN_MAX_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else {
            debug!(
                "Proceeding to refresh from domain at level {}",
                ctx.domain_version
            );
        };

        // == ⚠️  Below this point we begin to make changes! ==

        // Update the d_uuid. This is what defines us as being part of this repl topology!
        self.be_txn.set_db_d_uuid(ctx.domain_uuid).map_err(|e| {
            error!("Failed to reset domain uuid");
            e
        })?;

        // Do we need to reset our s_uuid to avoid potential RUV conflicts?
        //   - I don't think so, since the refresh is supplying and rebuilding
        //     our local state.

        // Delete all entries - *proper delete, not just tombstone!*

        // Apply the schema entries first.

        // We need to reload schema now!
        self.reload_schema().map_err(|e| {
            error!("Failed to reload schema");
            e
        })?;

        // We have to reindex to force all the existing indexes to be dumped
        // and recreated before we start to import.
        self.reindex().map_err(|e| {
            error!("Failed to reload schema");
            e
        })?;

        // Apply the domain info entry / system info / system config entry?

        // NOTE: The domain info we recieve here will have the domain version populated!

        self.reload_domain_info().map_err(|e| {
            error!("Failed to reload domain info");
            e
        })?;

        // Mark that everything changed so that post commit hooks function as expected.
        self.changed_schema = true;
        self.changed_acp = true;
        self.changed_oauth2 = true;
        self.changed_domain = true;
        /*
        self.changed_uuid
            .extend(
                commit_cand.iter().map(|e| e.get_uuid())
            );
        */

        // That's it! We are GOOD to go!

        // Create all the entries. Note we don't hit plugins here beside post repl plugs.

        // Run post repl plugins

        Ok(())
    }
}
