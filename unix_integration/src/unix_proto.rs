use crate::idprovider::interface::UserToken;
use crate::pam_data::PamData;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NssUser {
    pub name: String,
    pub gid: u32,
    pub gecos: String,
    pub homedir: String,
    pub shell: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NssGroup {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub enum PamMessageStyle {
    #[default]
    PamPromptEchoOff,
    PamPromptEchoOn,
    PamErrorMsg,
    PamTextInfo,
}

impl PamMessageStyle {
    pub fn value(&self) -> i32 {
        match *self {
            PamMessageStyle::PamPromptEchoOff => 1,
            PamMessageStyle::PamPromptEchoOn => 2,
            PamMessageStyle::PamErrorMsg => 3,
            PamMessageStyle::PamTextInfo => 4,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub enum CredType {
    #[default]
    Password,
    MFACode,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PamPrompt {
    pub style: PamMessageStyle,
    pub msg: String,
    pub timeout: Option<u64>, // timeout of None means use the config default
    pub cred_type: Option<CredType>,
    pub data: Option<PamData>,
}

impl PamPrompt {
    // Produce a typical password prompt
    pub fn passwd_prompt() -> Self {
        PamPrompt {
            style: PamMessageStyle::PamPromptEchoOff,
            msg: "Password: ".to_string(),
            timeout: None,
            cred_type: Some(CredType::Password),
            data: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PamCred {
    Password(String), // Will be stored in the cache
    MFACode(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    SshKey(String),
    NssAccounts,
    NssAccountByUid(u32),
    NssAccountByName(String),
    NssGroups,
    NssGroupByGid(u32),
    NssGroupByName(String),
    PamAuthenticateInit(String),
    PamAuthenticateStep(Option<PamCred>, Option<PamData>),
    PamAccountAllowed(String),
    PamAccountBeginSession(String),
    InvalidateCache,
    ClearCache,
    Status,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientResponse {
    SshKeys(Vec<String>),
    NssAccounts(Vec<NssUser>),
    NssAccount(Option<NssUser>),
    NssGroups(Vec<NssGroup>),
    NssGroup(Option<NssGroup>),
    PamStatus(Option<bool>),
    PamPrompt(PamPrompt),
    Ok,
    Error,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HomeDirectoryInfo {
    pub gid: u32,
    pub name: String,
    pub aliases: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TaskRequest {
    HomeDirectory(HomeDirectoryInfo),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TaskResponse {
    Success,
    Error(String),
}

#[derive(Debug)]
pub enum ProviderResult {
    PamPrompt(PamPrompt),
    UserToken(Option<UserToken>),
}

pub enum PamState {
    Uninitialized,
    Step(String),
}
