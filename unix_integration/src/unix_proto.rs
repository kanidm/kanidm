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

/* RFC8628: 3.2. Device Authorization Response */
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    pub interval: Option<u32>,
    /* The message is not part of RFC8628, but an add-on from MS. Listed
     * optional here to support all implementations. */
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PamAuthResponse {
    Unknown,
    Success,
    Denied,
    Password,
    DeviceAuthorizationGrant {
        data: DeviceAuthorizationResponse,
    },
    /// PAM must prompt for an authentication code
    MFACode {
        msg: String,
    },
    /// PAM will poll for an external response
    MFAPoll {
        /// Initial message to display as the polling begins.
        msg: String,
        /// Seconds between polling attempts.
        polling_interval: u32,
    },
    MFAPollWait,
    // CTAP2
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PamAuthRequest {
    Password {
        cred: String,
    },
    DeviceAuthorizationGrant {
        data: DeviceAuthorizationResponse,
    },
    MFACode {
        cred: String,
        data: Vec<String>,
    },
    MFAPoll {
        // poll_attempt: u32,
        data: Vec<String>,
    },
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
    PamAuthenticateStep(PamAuthRequest),
    PamAccountAllowed(String),
    PamAccountBeginSession(String),
    InvalidateCache,
    ClearCache,
    Status,
}

impl ClientRequest {
    /// Get a safe display version of the request, without credentials.
    pub fn as_safe_string(&self) -> String {
        match self {
            ClientRequest::SshKey(id) => format!("SshKey({})", id),
            ClientRequest::NssAccounts => "NssAccounts".to_string(),
            ClientRequest::NssAccountByUid(id) => format!("NssAccountByUid({})", id),
            ClientRequest::NssAccountByName(id) => format!("NssAccountByName({})", id),
            ClientRequest::NssGroups => "NssGroups".to_string(),
            ClientRequest::NssGroupByGid(id) => format!("NssGroupByGid({})", id),
            ClientRequest::NssGroupByName(id) => format!("NssGroupByName({})", id),
            ClientRequest::PamAuthenticateInit(id) => format!("PamAuthenticateInit({})", id),
            ClientRequest::PamAuthenticateStep(_) => "PamAuthenticateStep".to_string(),
            ClientRequest::PamAccountAllowed(id) => {
                format!("PamAccountAllowed({})", id)
            }
            ClientRequest::PamAccountBeginSession(_) => "PamAccountBeginSession".to_string(),
            ClientRequest::InvalidateCache => "InvalidateCache".to_string(),
            ClientRequest::ClearCache => "ClearCache".to_string(),
            ClientRequest::Status => "Status".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientResponse {
    SshKeys(Vec<String>),
    NssAccounts(Vec<NssUser>),
    NssAccount(Option<NssUser>),
    NssGroups(Vec<NssGroup>),
    NssGroup(Option<NssGroup>),

    PamStatus(Option<bool>),
    PamAuthenticateStepResponse(PamAuthResponse),

    Ok,
    Error,
}

impl From<PamAuthResponse> for ClientResponse {
    fn from(par: PamAuthResponse) -> Self {
        ClientResponse::PamAuthenticateStepResponse(par)
    }
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

#[test]
fn test_clientrequest_as_safe_string() {
    assert_eq!(
        ClientRequest::NssAccounts.as_safe_string(),
        "NssAccounts".to_string()
    );
    assert_eq!(
        ClientRequest::SshKey("cheese".to_string()).as_safe_string(),
        format!("SshKey({})", "cheese")
    );
}
