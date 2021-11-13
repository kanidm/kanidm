#[derive(Debug, StructOpt)]
pub struct Named {
    #[structopt()]
    pub name: String,
    #[structopt(flatten)]
    pub copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct DebugOpt {
    #[structopt(short = "d", long = "debug", env = "KANIDM_DEBUG")]
    pub debug: bool,
}

#[derive(Debug, StructOpt)]
pub struct CommonOpt {
    #[structopt(short = "d", long = "debug", env = "KANIDM_DEBUG")]
    pub debug: bool,
    #[structopt(short = "H", long = "url", env = "KANIDM_URL")]
    pub addr: Option<String>,
    #[structopt(short = "D", long = "name", env = "KANIDM_NAME")]
    pub username: Option<String>,
    #[structopt(parse(from_os_str), short = "C", long = "ca", env = "KANIDM_CA_PATH")]
    pub ca_path: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
pub struct GroupNamedMembers {
    #[structopt()]
    name: String,
    #[structopt()]
    members: Vec<String>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct GroupPosixOpt {
    #[structopt()]
    name: String,
    #[structopt(long = "gidnumber")]
    gidnumber: Option<u32>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub enum GroupPosix {
    #[structopt(name = "show")]
    Show(Named),
    #[structopt(name = "set")]
    Set(GroupPosixOpt),
}

#[derive(Debug, StructOpt)]
pub enum GroupOpt {
    #[structopt(name = "list")]
    List(CommonOpt),
    #[structopt(name = "get")]
    Get(Named),
    #[structopt(name = "create")]
    Create(Named),
    #[structopt(name = "delete")]
    Delete(Named),
    #[structopt(name = "list_members")]
    ListMembers(Named),
    #[structopt(name = "set_members")]
    SetMembers(GroupNamedMembers),
    #[structopt(name = "purge_members")]
    PurgeMembers(Named),
    #[structopt(name = "add_members")]
    AddMembers(GroupNamedMembers),
    #[structopt(name = "remove_members")]
    RemoveMembers(GroupNamedMembers),
    #[structopt(name = "posix")]
    Posix(GroupPosix),
}

#[derive(Debug, StructOpt)]
pub struct AccountCommonOpt {
    #[structopt()]
    account_id: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountCredentialSet {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedExpireDateTimeOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "datetime")]
    /// An rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// or the word "never", "clear" to remove account expiry.
    datetime: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedValidDateTimeOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "datetime")]
    /// An rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// or the word "any", "clear" to remove valid from enforcement.
    datetime: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedTagOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "tag")]
    tag: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountNamedTagPkOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "tag")]
    tag: String,
    #[structopt(name = "pubkey")]
    pubkey: String,
}

#[derive(Debug, StructOpt)]
pub struct AccountCreateOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(name = "display_name")]
    display_name: String,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub enum AccountCredential {
    /// Set this accounts password
    #[structopt(name = "set_password")]
    SetPassword(AccountCredentialSet),
    /// Register a new webauthn device to this account.
    #[structopt(name = "register_webauthn")]
    RegisterWebauthn(AccountNamedTagOpt),
    /// Remove a webauthn device from this account
    #[structopt(name = "remove_webauthn")]
    RemoveWebauthn(AccountNamedTagOpt),
    /// Set the TOTP credential of the account. If a TOTP already exists, on a successful
    /// registration, this will replace it.
    #[structopt(name = "register_totp")]
    RegisterTotp(AccountNamedOpt),
    /// Remove TOTP from the account. If no TOTP exists, no action is taken.
    #[structopt(name = "remove_totp")]
    RemoveTotp(AccountNamedOpt),
    /// Show the status of the accounts credentials.
    #[structopt(name = "status")]
    Status(AccountNamedOpt),
    /// Reset the accounts credentials, removing all TOTP, Webauthn, Passwords,
    /// and generate a new strong random password.
    #[structopt(name = "reset_credential")]
    GeneratePassword(AccountCredentialSet),
    /// Generate a new set of backup codes.
    #[structopt(name = "generate_backup_codes")]
    BackupCodeGenerate(AccountNamedOpt),
    /// Remove backup codes from the account.
    #[structopt(name = "remove_backup_codes")]
    BackupCodeRemove(AccountNamedOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountRadius {
    #[structopt(name = "show_secret")]
    Show(AccountNamedOpt),
    #[structopt(name = "generate_secret")]
    Generate(AccountNamedOpt),
    #[structopt(name = "delete_secret")]
    Delete(AccountNamedOpt),
}

#[derive(Debug, StructOpt)]
pub struct AccountPosixOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(long = "gidnumber")]
    gidnumber: Option<u32>,
    #[structopt(long = "shell")]
    shell: Option<String>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub enum AccountPosix {
    #[structopt(name = "show")]
    Show(AccountNamedOpt),
    #[structopt(name = "set")]
    Set(AccountPosixOpt),
    #[structopt(name = "set_password")]
    SetPassword(AccountNamedOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountSsh {
    #[structopt(name = "list_publickeys")]
    List(AccountNamedOpt),
    #[structopt(name = "add_publickey")]
    Add(AccountNamedTagPkOpt),
    #[structopt(name = "delete_publickey")]
    Delete(AccountNamedTagOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountValidity {
    #[structopt(name = "show")]
    Show(AccountNamedOpt),
    #[structopt(name = "expire_at")]
    ExpireAt(AccountNamedExpireDateTimeOpt),
    #[structopt(name = "begin_from")]
    BeginFrom(AccountNamedValidDateTimeOpt),
}

#[derive(Debug, StructOpt)]
pub enum AccountOpt {
    #[structopt(name = "credential")]
    Credential(AccountCredential),
    #[structopt(name = "radius")]
    Radius(AccountRadius),
    #[structopt(name = "posix")]
    Posix(AccountPosix),
    #[structopt(name = "ssh")]
    Ssh(AccountSsh),
    #[structopt(name = "list")]
    List(CommonOpt),
    #[structopt(name = "get")]
    Get(AccountNamedOpt),
    #[structopt(name = "create")]
    Create(AccountCreateOpt),
    #[structopt(name = "delete")]
    Delete(AccountNamedOpt),
    #[structopt(name = "validity")]
    Validity(AccountValidity),
}

#[derive(Debug, StructOpt)]
pub enum RecycleOpt {
    #[structopt(name = "list")]
    /// List objects that are in the recycle bin
    List(CommonOpt),
    #[structopt(name = "get")]
    /// Display an object from the recycle bin
    Get(Named),
    #[structopt(name = "revive")]
    /// Revive a recycled object into a live (accessible) state - this is the opposite of "delete"
    Revive(Named),
}

#[derive(Debug, StructOpt)]
pub struct LoginOpt {
    #[structopt(flatten)]
    pub copt: CommonOpt,
    #[structopt(short = "w", long = "webauthn")]
    pub webauthn: bool,
}

#[derive(Debug, StructOpt)]
pub struct LogoutOpt {
    #[structopt(short = "d", long = "debug", env = "KANIDM_DEBUG")]
    pub debug: bool,
    #[structopt(short = "H", long = "url", env = "KANIDM_URL")]
    pub addr: Option<String>,
    #[structopt(parse(from_os_str), short = "C", long = "ca", env = "KANIDM_CA_PATH")]
    pub ca_path: Option<PathBuf>,
    #[structopt()]
    pub username: Option<String>,
}

#[derive(Debug, StructOpt)]
pub enum SessionOpt {
    #[structopt(name = "list")]
    /// List current active sessions
    List(DebugOpt),
    #[structopt(name = "cleanup")]
    /// Remove sessions that have expired or are invalid.
    Cleanup(DebugOpt),
}

#[derive(Debug, StructOpt)]
pub struct FilterOpt {
    #[structopt()]
    filter: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct CreateOpt {
    #[structopt(parse(from_os_str))]
    file: PathBuf,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct ModifyOpt {
    #[structopt(flatten)]
    commonopts: CommonOpt,
    #[structopt()]
    filter: String,
    #[structopt(parse(from_os_str))]
    file: PathBuf,
}

#[derive(Debug, StructOpt)]
pub enum RawOpt {
    #[structopt(name = "search")]
    Search(FilterOpt),
    #[structopt(name = "create")]
    Create(CreateOpt),
    #[structopt(name = "modify")]
    Modify(ModifyOpt),
    #[structopt(name = "delete")]
    Delete(FilterOpt),
}

#[derive(Debug, StructOpt)]
pub enum SelfOpt {
    #[structopt(name = "whoami")]
    /// Show the current authenticated user's identity
    Whoami(CommonOpt),
    #[structopt(name = "set_password")]
    /// Set the current user's password
    SetPassword(CommonOpt),
}

#[derive(Debug, StructOpt)]
pub struct Oauth2BasicCreateOpt {
    #[structopt(flatten)]
    nopt: Named,
    #[structopt(name = "displayname")]
    displayname: String,
    #[structopt(name = "origin")]
    origin: String,
}

#[derive(Debug, StructOpt)]
pub struct Oauth2SetImplicitScopes {
    #[structopt(flatten)]
    nopt: Named,
    #[structopt(name = "scopes")]
    scopes: Vec<String>,
}

#[derive(Debug, StructOpt)]
pub struct Oauth2CreateScopeMapOpt {
    #[structopt(flatten)]
    nopt: Named,
    #[structopt(name = "group")]
    group: String,
    #[structopt(name = "scopes")]
    scopes: Vec<String>,
}

#[derive(Debug, StructOpt)]
pub struct Oauth2DeleteScopeMapOpt {
    #[structopt(flatten)]
    nopt: Named,
    #[structopt(name = "group")]
    group: String,
}

#[derive(Debug, StructOpt)]
pub enum Oauth2Opt {
    #[structopt(name = "list")]
    /// List all configured oauth2 resource servers
    List(CommonOpt),
    #[structopt(name = "get")]
    /// Display a selected oauth2 resource server
    Get(Named),
    // #[structopt(name = "set")]
    // /// Set options for a selected oauth2 resource server
    // Set(),
    #[structopt(name = "create")]
    /// Create a new oauth2 resource server
    CreateBasic(Oauth2BasicCreateOpt),
    #[structopt(name = "set_implicit_scopes")]
    /// Set the list of scopes that are granted to all valid accounts.
    SetImplictScopes(Oauth2SetImplicitScopes),
    #[structopt(name = "create_scope_map")]
    /// Add a new mapping from a group to what scopes it provides
    CreateScopeMap(Oauth2CreateScopeMapOpt),
    #[structopt(name = "delete_scope_map")]
    /// Remove a mapping from groups to scopes
    DeleteScopeMap(Oauth2DeleteScopeMapOpt),
    #[structopt(name = "reset_secrets")]
    /// Reset the secrets associated to this resource server
    ResetSecrets(Named),
    #[structopt(name = "delete")]
    /// Delete a oauth2 resource server
    Delete(Named),
    #[structopt(name = "enable_pkce")]
    /// Enable PKCE on this oauth2 resource server. This defaults to being enabled.
    EnablePkce(Named),
    /// Disable PKCE on this oauth2 resource server to work around insecure clients that
    /// may not support it. You should request the client to enable PKCE!
    #[structopt(name = "warning_insecure_client_disable_pkce")]
    DisablePkce(Named),
    #[structopt(name = "warning_enable_legacy_crytpo")]
    /// Enable legacy signing crypto on this oauth2 resource server. This defaults to being disabled.
    /// You only need to enable this for openid clients that do not support modern crytopgraphic
    /// operations.
    EnableLegacyCrypto(Named),
    /// Disable legacy signing crypto on this oauth2 resource server. This is the default.
    #[structopt(name = "disable_legacy_crypto")]
    DisableLegacyCrypto(Named),
}

#[derive(Debug, StructOpt)]
pub enum DomainOpt {
    #[structopt(name = "show")]
    /// Show information about this systems domain
    Show(CommonOpt),
    #[structopt(name = "reset_token_key")]
    /// Reset this domain token signing key. This will cause all user sessions to be
    /// invalidated (logged out).
    ResetTokenKey(CommonOpt),
}

#[derive(Debug, StructOpt)]
pub enum SystemOpt {
    #[structopt(name = "oauth2")]
    /// Configure and display oauth2/oidc resource server configuration
    Oauth2(Oauth2Opt),
    #[structopt(name = "domain")]
    /// Configure and display domain configuration
    Domain(DomainOpt),
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Kanidm Client Utility")]
pub enum KanidmClientOpt {
    #[structopt(name = "login")]
    /// Login to an account to use with future cli operations
    Login(LoginOpt),
    #[structopt(name = "logout")]
    /// Logout of an active cli session
    Logout(LogoutOpt),
    #[structopt(name = "session")]
    /// Manage active cli sessions
    Session(SessionOpt),
    #[structopt(name = "self")]
    /// Actions for the current authenticated account
    CSelf(SelfOpt),
    #[structopt(name = "account")]
    /// Account operations
    Account(AccountOpt),
    #[structopt(name = "group")]
    /// Group operations
    Group(GroupOpt),
    #[structopt(name = "system")]
    /// System configuration operations
    System(SystemOpt),
    #[structopt(name = "recycle_bin")]
    /// Recycle Bin operations
    Recycle(RecycleOpt),
    #[structopt(name = "raw")]
    /// Unsafe - low level, raw database operations.
    Raw(RawOpt),
}
