#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    SshKey(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientResponse {
    SshKeys(Vec<String>),
}
