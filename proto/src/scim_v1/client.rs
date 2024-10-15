use serde::{Deserialize, Serialize};
use sshkey_attest::proto::PublicKey as SshPublicKey;

pub type ScimSshPublicKeys = Vec<ScimSshPublicKey>;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScimSshPublicKey {
    pub label: String,
    pub value: SshPublicKey,
}
