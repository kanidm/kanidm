use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;
use webauthn_rs::proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

// These proto implementations are here because they have public definitions

/* ===== errors ===== */

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SchemaError {
    NotImplemented,
    NoClassFound,
    InvalidClass(Vec<String>),
    MissingMustAttribute(Vec<String>),
    InvalidAttribute(String),
    InvalidAttributeSyntax(String),
    EmptyFilter,
    Corrupted,
    PhantomAttribute(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PluginError {
    AttrUnique(String),
    Base(String),
    ReferentialIntegrity(String),
    PasswordImport(String),
    Oauth2Secrets,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConsistencyError {
    Unknown,
    // Class, Attribute
    SchemaClassMissingAttribute(String, String),
    SchemaClassPhantomAttribute(String, String),
    SchemaUuidNotUnique(Uuid),
    QueryServerSearchFailure,
    EntryUuidCorrupt(u64),
    UuidIndexCorrupt(String),
    UuidNotUnique(String),
    RefintNotUpheld(u64),
    MemberOfInvalid(u64),
    InvalidAttributeType(String),
    DuplicateUniqueAttribute(String),
    InvalidSpn(u64),
    SqliteIntegrityFailure,
    BackendAllIdsSync,
    BackendIndexSync,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum OperationError {
    SessionExpired,
    EmptyRequest,
    Backend,
    NoMatchingEntries,
    NoMatchingAttributes,
    CorruptedEntry(u64),
    CorruptedIndex(String),
    ConsistencyError(Vec<Result<(), ConsistencyError>>),
    SchemaViolation(SchemaError),
    Plugin(PluginError),
    FilterGeneration,
    FilterUuidResolution,
    InvalidAttributeName(String),
    InvalidAttribute(String),
    InvalidDbState,
    InvalidCacheState,
    InvalidValueState,
    InvalidEntryId,
    InvalidRequestState,
    InvalidState,
    InvalidEntryState,
    InvalidUuid,
    InvalidReplChangeId,
    InvalidAcpState(String),
    InvalidSchemaState(String),
    InvalidAccountState(String),
    BackendEngine,
    SqliteError, //(RusqliteError)
    FsError,
    SerdeJsonError,
    SerdeCborError,
    AccessDenied,
    NotAuthenticated,
    InvalidAuthState(String),
    InvalidSessionState,
    SystemProtectedObject,
    SystemProtectedAttribute,
    PasswordTooWeak,
    PasswordTooShort(usize),
    PasswordEmpty,
    PasswordBadListed,
    CryptographyError,
    ResourceLimit,
    QueueDisconnected,
    Webauthn,
}

impl PartialEq for OperationError {
    fn eq(&self, other: &Self) -> bool {
        // We do this to avoid InvalidPassword being checked as it's not
        // derive PartialEq. Generally we only use the PartialEq for TESTING
        // anyway.
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

/* ===== higher level types ===== */
// These are all types that are conceptually layers ontop of entry and
// friends. They allow us to process more complex requests and provide
// domain specific fields for the purposes of IDM, over the normal
// entry/ava/filter types. These related deeply to schema.

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    pub name: String,
    pub uuid: String,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ name: {}, ", self.name)?;
        write!(f, "uuid: {} ]", self.uuid)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claim {
    pub name: String,
    pub uuid: String,
    // These can be ephemeral, or shortlived in a session.
    // some may even need requesting.
    // pub expiry: DateTime
}

/*
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Application {
    pub name: String,
    pub uuid: String,
}
*/

#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Anonymous,
    UnixPassword,
    Password,
    GeneratedPassword,
    Webauthn,
    PasswordMfa,
    // PasswordWebauthn,
    // WebauthnVerified,
    // PasswordWebauthnVerified,
}

/// The currently authenticated user, and any required metadata for them
/// to properly authorise them. This is similar in nature to oauth and the krb
/// PAC/PAD structures. Currently we only use this internally, but we should
/// consider making it "parseable" by the client so they can have per-session
/// group/authorisation data.
///
/// This structure and how it works will *very much* change over time from this
/// point onward!
///
/// It's likely that this must have a relationship to the server's user structure
/// and to the Entry so that filters or access controls can be applied.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct UserAuthToken {
    pub session_id: Uuid,
    pub auth_type: AuthType,
    // When this token should be considered expired. Interpretation
    // may depend on the client application.
    pub expiry: time::OffsetDateTime,
    pub uuid: Uuid,
    // pub name: String,
    pub spn: String,
    // pub groups: Vec<Group>,
    // pub claims: Vec<Claim>,
    // Should we just retrieve these inside the server instead of in the uat?
    // or do we want per-session limit capabilities?
    pub lim_uidx: bool,
    pub lim_rmax: usize,
    pub lim_pmax: usize,
    pub lim_fmax: usize,
}

impl fmt::Display for UserAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // writeln!(f, "name: {}", self.name)?;
        writeln!(f, "spn: {}", self.spn)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        /*
        writeln!(f, "display: {}", self.displayname)?;
        for group in &self.groups {
            writeln!(f, "group: {:?}", group.name)?;
        }
        for claim in &self.claims {
            writeln!(f, "claim: {:?}", claim)?;
        }
        */
        writeln!(f, "token expiry: {}", self.expiry)
    }
}

// UAT will need a downcast to Entry, which adds in the claims to the entry
// for the purpose of filtering.

// This is similar to uat, but omits claims (they have no role in radius), and adds
// the radius secret field.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RadiusAuthToken {
    pub name: String,
    pub displayname: String,
    pub uuid: String,
    pub secret: String,
    pub groups: Vec<Group>,
}

impl fmt::Display for RadiusAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "displayname: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "secret: {}", self.secret)?;
        self.groups
            .iter()
            .try_for_each(|g| writeln!(f, "group: {}", g))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnixGroupToken {
    pub name: String,
    pub spn: String,
    pub uuid: String,
    pub gidnumber: u32,
}

impl fmt::Display for UnixGroupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ spn: {}, ", self.spn)?;
        write!(f, "gidnumber: {} ", self.gidnumber)?;
        write!(f, "name: {}, ", self.name)?;
        write!(f, "uuid: {} ]", self.uuid)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupUnixExtend {
    pub gidnumber: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnixUserToken {
    pub name: String,
    pub spn: String,
    pub displayname: String,
    pub gidnumber: u32,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    pub groups: Vec<UnixGroupToken>,
    pub sshkeys: Vec<String>,
    // The default value of bool is false.
    #[serde(default)]
    pub valid: bool,
}

impl fmt::Display for UnixUserToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "---")?;
        writeln!(f, "spn: {}", self.spn)?;
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "displayname: {}", self.displayname)?;
        writeln!(f, "uuid: {}", self.uuid)?;
        match &self.shell {
            Some(s) => writeln!(f, "shell: {}", s)?,
            None => writeln!(f, "shell: <none>")?,
        }
        self.sshkeys
            .iter()
            .try_for_each(|s| writeln!(f, "ssh_publickey: {}", s))?;
        self.groups
            .iter()
            .try_for_each(|g| writeln!(f, "group: {}", g))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountUnixExtend {
    pub gidnumber: Option<u32>,
    pub shell: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CredentialDetailType {
    Password,
    GeneratedPassword,
    Webauthn(Vec<String>),
    /// totp, webauthn
    PasswordMfa(bool, Vec<String>, usize),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialDetail {
    pub uuid: Uuid,
    pub claims: Vec<String>,
    pub type_: CredentialDetailType,
}

impl fmt::Display for CredentialDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "uuid: {}", self.uuid)?;
        writeln!(f, "claims:")?;
        for claim in &self.claims {
            writeln!(f, " * {}", claim)?;
        }
        match &self.type_ {
            CredentialDetailType::Password => writeln!(f, "password: set"),
            CredentialDetailType::GeneratedPassword => writeln!(f, "generated password: set"),
            CredentialDetailType::Webauthn(labels) => {
                if labels.is_empty() {
                    writeln!(f, "webauthn: no authenticators")
                } else {
                    writeln!(f, "webauthn:")?;
                    for label in labels {
                        writeln!(f, " * {}", label)?;
                    }
                    write!(f, "")
                }
            }
            CredentialDetailType::PasswordMfa(totp, labels, backup_code) => {
                writeln!(f, "password: set")?;
                if *totp {
                    writeln!(f, "totp: enabled")?;
                } else {
                    writeln!(f, "totp: disabled")?;
                }
                if *backup_code > 0 {
                    writeln!(f, "backup_code: enabled")?;
                } else {
                    writeln!(f, "backup_code: disabled")?;
                }
                if labels.is_empty() {
                    writeln!(f, "webauthn: no authenticators")
                } else {
                    writeln!(f, "webauthn:")?;
                    for label in labels {
                        writeln!(f, " * {}", label)?;
                    }
                    write!(f, "")
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialStatus {
    pub creds: Vec<CredentialDetail>,
}

impl fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for cred in &self.creds {
            writeln!(f, "---")?;
            cred.fmt(f)?;
        }
        writeln!(f, "---")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupCodesView {
    // Or use SetCredentialResponse::BackupCodes?
    pub backup_codes: Vec<String>,
}

/* ===== low level proto types ===== */

// ProtoEntry vs Entry
// There is a good future reason for this seperation. It allows changing
// the in memory server core entry type, without affecting the protoEntry type
//

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct Entry {
    pub attrs: BTreeMap<String, Vec<String>>,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "---")?;
        self.attrs
            .iter()
            .try_for_each(|(k, vs)| vs.iter().try_for_each(|v| writeln!(f, "{}: {}", k, v)))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Filter {
    // This is attr - value
    #[serde(alias = "Eq")]
    Eq(String, String),
    #[serde(alias = "Sub")]
    Sub(String, String),
    #[serde(alias = "Pres")]
    Pres(String),
    #[serde(alias = "Or")]
    Or(Vec<Filter>),
    #[serde(alias = "And")]
    And(Vec<Filter>),
    #[serde(alias = "AndNot")]
    AndNot(Box<Filter>),
    #[serde(rename = "self", alias = "Self")]
    SelfUuid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Modify {
    Present(String, String),
    Removed(String, String),
    Purged(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModifyList {
    pub mods: Vec<Modify>,
}

impl ModifyList {
    pub fn new_list(mods: Vec<Modify>) -> Self {
        ModifyList { mods }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRequest {
    pub filter: Filter,
}

impl SearchRequest {
    pub fn new(filter: Filter) -> Self {
        SearchRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
}

impl SearchResponse {
    pub fn new(entries: Vec<Entry>) -> Self {
        SearchResponse { entries }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequest {
    pub entries: Vec<Entry>,
}

impl CreateRequest {
    pub fn new(entries: Vec<Entry>) -> Self {
        CreateRequest { entries }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub filter: Filter,
}

impl DeleteRequest {
    pub fn new(filter: Filter) -> Self {
        DeleteRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModifyRequest {
    // Probably needs a modlist?
    pub filter: Filter,
    pub modlist: ModifyList,
}

impl ModifyRequest {
    pub fn new(filter: Filter, modlist: ModifyList) -> Self {
        ModifyRequest { filter, modlist }
    }
}

// Login is a multi-step process potentially. First the client says who they
// want to request
//
// we respond with a set of possible authentications that can proceed, and perhaps
// we indicate which options must/may?
//
// The client can then step and negotiate each.
//
// This continues until a LoginSuccess, or LoginFailure is returned.
//
// On loginSuccess, we send a cookie, and that allows the token to be
// generated. The cookie can be shared between servers.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),
    Webauthn(PublicKeyCredential),
    BackupCode(String),
}

impl fmt::Debug for AuthCredential {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthCredential::Anonymous => write!(fmt, "Anonymous"),
            AuthCredential::Password(_) => write!(fmt, "Password(_)"),
            AuthCredential::Totp(_) => write!(fmt, "TOTP(_)"),
            AuthCredential::Webauthn(_) => write!(fmt, "Webauthn(_)"),
            AuthCredential::BackupCode(_) => write!(fmt, "BackupCode(_)"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AuthMech {
    Anonymous,
    Password,
    PasswordMfa,
    Webauthn,
    // WebauthnVerified,
    // PasswordWebauthnVerified
}

impl PartialEq for AuthMech {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl fmt::Display for AuthMech {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMech::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthMech::Password => write!(f, "Passwold Only"),
            AuthMech::PasswordMfa => write!(f, "TOTP or Token, and Password"),
            AuthMech::Webauthn => write!(f, "Webauthn Token"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthStep {
    // name
    Init(String),
    // We want to talk to you like this.
    Begin(AuthMech),
    // Step
    Cred(AuthCredential),
    // Should we have a "finalise" type to attempt to finish based on
    // what we have given?
}

// Request auth for identity X with roles Y?
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub step: AuthStep,
}

// Respond with the list of auth types and nonce, etc.
// It can also contain a denied, or success.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AuthAllowed {
    Anonymous,
    BackupCode,
    Password,
    Totp,
    Webauthn(RequestChallengeResponse),
}

impl PartialEq for AuthAllowed {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for AuthAllowed {}

impl Ord for AuthAllowed {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.eq(other) {
            Ordering::Equal
        } else {
            // Relies on the fact that match is executed in order!
            match (self, other) {
                (AuthAllowed::Anonymous, _) => Ordering::Less,
                (_, AuthAllowed::Anonymous) => Ordering::Greater,
                (AuthAllowed::Password, _) => Ordering::Less,
                (_, AuthAllowed::Password) => Ordering::Greater,
                (AuthAllowed::BackupCode, _) => Ordering::Less,
                (_, AuthAllowed::BackupCode) => Ordering::Greater,
                (AuthAllowed::Totp, _) => Ordering::Less,
                (_, AuthAllowed::Totp) => Ordering::Greater,
                (AuthAllowed::Webauthn(_), _) => Ordering::Less,
                // Unreachable
                // (_, AuthAllowed::Webauthn(_)) => Ordering::Greater,
            }
        }
    }
}

impl PartialOrd for AuthAllowed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for AuthAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthAllowed::Anonymous => write!(f, "Anonymous (no credentials)"),
            AuthAllowed::Password => write!(f, "Password"),
            AuthAllowed::BackupCode => write!(f, "Backup Code"),
            AuthAllowed::Totp => write!(f, "TOTP"),
            AuthAllowed::Webauthn(_) => write!(f, "Webauthn Token"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthState {
    // You need to select how you want to talk to me.
    Choose(Vec<AuthMech>),
    // Continue to auth, allowed mechanisms/challenges listed.
    Continue(Vec<AuthAllowed>),
    // Something was bad, your session is terminated and no cookie.
    Denied(String),
    // Everything is good, your bearer header has been issued and is within
    // the result.
    Success(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub sessionid: Uuid,
    pub state: AuthState,
}

// Types needed for setting credentials
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SetCredentialRequest {
    Password(String),
    GeneratePassword,
    TotpGenerate,
    TotpVerify(Uuid, u32),
    TotpAcceptSha1(Uuid),
    TotpRemove,
    // Start the rego.
    WebauthnBegin(String),
    // Finish it.
    WebauthnRegister(Uuid, RegisterPublicKeyCredential),
    // Remove
    WebauthnRemove(String),
    GenerateBackupCode,
    BackupCodeRemove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

impl fmt::Display for TotpAlgo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TotpAlgo::Sha1 => write!(f, "SHA1"),
            TotpAlgo::Sha256 => write!(f, "SHA256"),
            TotpAlgo::Sha512 => write!(f, "SHA512"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    pub accountname: String,
    pub issuer: String,
    pub secret: Vec<u8>,
    pub algo: TotpAlgo,
    pub step: u64,
}

impl TotpSecret {
    /// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    pub fn to_uri(&self) -> String {
        // label = accountname / issuer (“:” / “%3A”) *”%20” accountname
        // This is already done server side but paranoia is good!
        let accountname = self
            .accountname
            .replace(":", "")
            .replace("%3A", "")
            .replace(" ", "%20");
        let issuer = self
            .issuer
            .replace(":", "")
            .replace("%3A", "")
            .replace(" ", "%20");
        let label = format!("{}:{}", issuer, accountname);
        let algo = self.algo.to_string();
        let secret = self.get_secret();
        let period = self.step;
        format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm={}&digits=6&period={}",
            label, secret, issuer, algo, period
        )
    }

    pub fn get_secret(&self) -> String {
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.secret)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SetCredentialResponse {
    Success,
    Token(String),
    TotpCheck(Uuid, TotpSecret),
    TotpInvalidSha1(Uuid),
    WebauthnCreateChallenge(Uuid, CreationChallengeResponse),
    BackupCodes(Vec<String>),
}

/* Recycle Requests area */

// Only two actions on recycled is possible. Search and Revive.

/*
pub struct SearchRecycledRequest {
    pub filter: Filter,
}

impl SearchRecycledRequest {
    pub fn new(filter: Filter) -> Self {
        SearchRecycledRequest { filter }
    }
}
*/

// Need a search response here later.

/*
pub struct ReviveRecycledRequest {
    pub filter: Filter,
}

impl ReviveRecycledRequest {
    pub fn new(filter: Filter) -> Self {
        ReviveRecycledRequest { filter }
    }
}
*/

// This doesn't need seralise because it's only accessed via a "get".
/*
#[derive(Debug, Default)]
pub struct WhoamiRequest {}

impl WhoamiRequest {
    pub fn new() -> Self {
        Default::default()
    }
}
*/

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoamiResponse {
    // Should we just embed the entry? Or destructure it?
    pub youare: Entry,
    pub uat: UserAuthToken,
}

impl WhoamiResponse {
    pub fn new(e: Entry, uat: UserAuthToken) -> Self {
        WhoamiResponse { youare: e, uat }
    }
}

// Simple string value provision.
#[derive(Debug, Serialize, Deserialize)]
pub struct SingleStringRequest {
    pub value: String,
}

impl SingleStringRequest {
    pub fn new(s: String) -> Self {
        SingleStringRequest { value: s }
    }
}
// Use OperationResponse here ...

#[cfg(test)]
mod tests {
    use crate::v1::Filter as ProtoFilter;
    use crate::v1::{TotpAlgo, TotpSecret};

    #[test]
    fn test_protofilter_simple() {
        let pf: ProtoFilter = ProtoFilter::Pres("class".to_string());

        println!("{:?}", serde_json::to_string(&pf).expect("JSON failure"));
    }

    #[test]
    fn totp_to_string() {
        let totp = TotpSecret {
            accountname: "william".to_string(),
            issuer: "blackhats".to_string(),
            secret: vec![0xaa, 0xbb, 0xcc, 0xdd],
            step: 30,
            algo: TotpAlgo::Sha256,
        };
        let s = totp.to_uri();
        assert!(s == "otpauth://totp/blackhats:william?secret=VK54ZXI&issuer=blackhats&algorithm=SHA256&digits=6&period=30");

        // check that invalid issuer/accounts are cleaned up.
        let totp = TotpSecret {
            accountname: "william:%3A".to_string(),
            issuer: "blackhats australia".to_string(),
            secret: vec![0xaa, 0xbb, 0xcc, 0xdd],
            step: 30,
            algo: TotpAlgo::Sha256,
        };
        let s = totp.to_uri();
        assert!(s == "otpauth://totp/blackhats%20australia:william?secret=VK54ZXI&issuer=blackhats%20australia&algorithm=SHA256&digits=6&period=30");
    }
}
