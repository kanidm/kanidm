use serde::{Deserialize, Serialize};

/* This is the definition for extra data to be sent along with a pam_prompt
 * request. It will be sent back to the idprovider to continue an auth attempt.
 */
#[derive(Serialize, Deserialize, Debug)]
pub struct PamData {}
