use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct Named {
    pub name: String,
    #[clap(flatten)]
    pub copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct DebugOpt {
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
}

#[derive(Debug, Args)]
pub struct CommonOpt {
    // TODO: this should probably be a flag, or renamed to log level if it's a level
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
    #[clap(short = 'H', long = "url", env = "KANIDM_URL")]
    pub addr: Option<String>,
    /// User which will initiate requests
    #[clap(short = 'D', long = "name", env = "KANIDM_NAME")]
    pub username: Option<String>,
    /// Path to a CA certificate file
    #[clap(parse(from_os_str), short = 'C', long = "ca", env = "KANIDM_CA_PATH")]
    pub ca_path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct GroupNamedMembers {
    name: String,
    members: Vec<String>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct GroupPosixOpt {
    name: String,
    #[clap(long)]
    gidnumber: Option<u32>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum GroupPosix {
    #[clap(name = "show")]
    Show(Named),
    #[clap(name = "set")]
    Set(GroupPosixOpt),
}

#[derive(Debug, Subcommand)]
pub enum GroupOpt {
    #[clap(name = "list")]
    List(CommonOpt),
    #[clap(name = "get")]
    Get(Named),
    #[clap(name = "create")]
    Create(Named),
    #[clap(name = "delete")]
    Delete(Named),
    #[clap(name = "list_members")]
    ListMembers(Named),
    #[clap(name = "set_members")]
    SetMembers(GroupNamedMembers),
    #[clap(name = "purge_members")]
    PurgeMembers(Named),
    #[clap(name = "add_members")]
    AddMembers(GroupNamedMembers),
    #[clap(name = "remove_members")]
    RemoveMembers(GroupNamedMembers),
    #[clap(name = "posix")]
    Posix {
        #[clap(subcommand)]
        commands: GroupPosix,
    },
}

#[derive(Debug, Args)]
pub struct AccountCommonOpt {
    #[clap()]
    account_id: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct AccountNamedExpireDateTimeOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "datetime")]
    /// An rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// or the word "never", "clear" to remove account expiry.
    datetime: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedValidDateTimeOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "datetime")]
    /// An rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// or the word "any", "clear" to remove valid from enforcement.
    datetime: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedTagOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "tag")]
    tag: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedTagPkOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "tag")]
    tag: String,
    #[clap(name = "pubkey")]
    pubkey: String,
}

#[derive(Debug, Args)]
/// Command-line options for account credental use_reset_token
pub struct UseResetTokenOpt {
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "token")]
    token: String,
}

#[derive(Debug, Args)]
pub struct AccountCreateOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(name = "display_name")]
    display_name: String,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum AccountCredential {
    /// Interactively update/change the credentials for an account
    #[clap(name = "update")]
    Update(AccountNamedOpt),
    /// Using a reset token, interactively reset credentials for a user
    #[clap(name = "use_reset_token")]
    UseResetToken(UseResetTokenOpt),
    /// Create a reset token that can be given to another person so they can
    /// recover or reset their account credentials.
    #[clap(name = "create_reset_token")]
    CreateResetToken(AccountNamedOpt),
}

/// RADIUS secret management
#[derive(Debug, Subcommand)]
pub enum AccountRadius {
    /// Show the RADIUS secret for a user.
    #[clap(name = "show_secret")]
    Show(AccountNamedOpt),
    /// Generate a randomized RADIUS secret for a user.
    #[clap(name = "generate_secret")]
    Generate(AccountNamedOpt),
    #[clap(name = "delete_secret")]
    /// Remove the configured RADIUS secret for the user.
    DeleteSecret(AccountNamedOpt),
}

#[derive(Debug, Args)]
pub struct AccountPosixOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(long)]
    gidnumber: Option<u32>,
    #[clap(long)]
    shell: Option<String>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum AccountPosix {
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    #[clap(name = "set")]
    Set(AccountPosixOpt),
    #[clap(name = "set_password")]
    SetPassword(AccountNamedOpt),
}

#[derive(Debug, Args)]
pub struct AccountPersonOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(long, short, help="Set the mail address, can be set multiple times for multiple addresses.")]
    mail: Option<Vec<String>>,
    #[clap(long, short, help="Set the legal name for the person.")]
    legalname: Option<String>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum AccountPerson {
    #[clap(name = "extend")]
    Extend(AccountPersonOpt),
    #[clap(name = "set")]
    Set(AccountPersonOpt),
}

#[derive(Debug, Subcommand)]
pub enum AccountSsh {
    #[clap(name = "list_publickeys")]
    List(AccountNamedOpt),
    #[clap(name = "add_publickey")]
    Add(AccountNamedTagPkOpt),
    #[clap(name = "delete_publickey")]
    Delete(AccountNamedTagOpt),
}

#[derive(Debug, Subcommand)]
pub enum AccountValidity {
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    #[clap(name = "expire_at")]
    ExpireAt(AccountNamedExpireDateTimeOpt),
    #[clap(name = "begin_from")]
    BeginFrom(AccountNamedValidDateTimeOpt),
}

#[derive(Debug, Subcommand)]
pub enum AccountOpt {
    #[clap(name = "credential")]
    Credential {
        #[clap(subcommand)]
        commands: AccountCredential,
    },
    #[clap(name = "radius")]
    Radius {
        #[clap(subcommand)]
        commands: AccountRadius,
    },
    #[clap(name = "posix")]
    Posix {
        #[clap(subcommand)]
        commands: AccountPosix,
    },
    #[clap(name = "person")]
    Person {
        #[clap(subcommand)]
        commands: AccountPerson,
    },
    #[clap(name = "ssh")]
    Ssh {
        #[clap(subcommand)]
        commands: AccountSsh,
    },
    #[clap(name = "list")]
    List(CommonOpt),
    #[clap(name = "get")]
    Get(AccountNamedOpt),
    #[clap(name = "create")]
    Create(AccountCreateOpt),
    #[clap(name = "delete")]
    Delete(AccountNamedOpt),
    #[clap(name = "validity")]
    Validity {
        #[clap(subcommand)]
        commands: AccountValidity,
    },
}

#[derive(Debug, Subcommand)]
pub enum RecycleOpt {
    #[clap(name = "list")]
    /// List objects that are in the recycle bin
    List(CommonOpt),
    #[clap(name = "get")]
    /// Display an object from the recycle bin
    Get(Named),
    #[clap(name = "revive")]
    /// Revive a recycled object into a live (accessible) state - this is the opposite of "delete"
    Revive(Named),
}

#[derive(Debug, Args)]
pub struct LoginOpt {
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(short, long)]
    webauthn: bool,
}

#[derive(Debug, Args)]
pub struct LogoutOpt {
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
    #[clap(short = 'H', long = "url", env = "KANIDM_URL")]
    pub addr: Option<String>,
    #[clap(parse(from_os_str), short = 'C', long = "ca", env = "KANIDM_CA_PATH")]
    pub ca_path: Option<PathBuf>,
    #[clap()]
    pub username: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum SessionOpt {
    #[clap(name = "list")]
    /// List current active sessions
    List(DebugOpt),
    #[clap(name = "cleanup")]
    /// Remove sessions that have expired or are invalid.
    Cleanup(DebugOpt),
}

#[derive(Debug, Args)]
pub struct FilterOpt {
    #[clap()]
    filter: String,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Args)]
pub struct CreateOpt {
    #[clap(parse(from_os_str))]
    file: PathBuf,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Args)]
pub struct ModifyOpt {
    #[clap(flatten)]
    commonopts: CommonOpt,
    #[clap()]
    filter: String,
    #[clap(parse(from_os_str))]
    file: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum RawOpt {
    #[clap(name = "search")]
    Search(FilterOpt),
    #[clap(name = "create")]
    Create(CreateOpt),
    #[clap(name = "modify")]
    Modify(ModifyOpt),
    #[clap(name = "delete")]
    Delete(FilterOpt),
}

#[derive(Debug, Subcommand)]
pub enum SelfOpt {
    /// Show the current authenticated user's identity
    Whoami(CommonOpt),
    #[clap(name = "set_password")]
    /// Set the current user's password
    SetPassword(CommonOpt),
}

#[derive(Debug, Args)]
pub struct Oauth2BasicCreateOpt {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "displayname")]
    displayname: String,
    #[clap(name = "origin")]
    origin: String,
}

#[derive(Debug, Args)]
pub struct Oauth2SetDisplayname {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "displayname")]
    displayname: String,
}

#[derive(Debug, Args)]
pub struct Oauth2SetImplicitScopes {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "scopes")]
    scopes: Vec<String>,
}

#[derive(Debug, Args)]
pub struct Oauth2CreateScopeMapOpt {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "group")]
    group: String,
    #[clap(name = "scopes")]
    scopes: Vec<String>,
}

#[derive(Debug, Args)]
pub struct Oauth2DeleteScopeMapOpt {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "group")]
    group: String,
}

#[derive(Debug, Subcommand)]
pub enum Oauth2Opt {
    #[clap(name = "list")]
    /// List all configured oauth2 resource servers
    List(CommonOpt),
    #[clap(name = "get")]
    /// Display a selected oauth2 resource server
    Get(Named),
    // #[clap(name = "set")]
    // /// Set options for a selected oauth2 resource server
    // Set(),
    #[clap(name = "create")]
    /// Create a new oauth2 resource server
    CreateBasic(Oauth2BasicCreateOpt),
    #[clap(name = "set_implicit_scopes")]
    /// Set the list of scopes that are granted to all valid accounts.
    SetImplictScopes(Oauth2SetImplicitScopes),
    #[clap(name = "create_scope_map")]
    /// Add a new mapping from a group to what scopes it provides
    CreateScopeMap(Oauth2CreateScopeMapOpt),
    #[clap(name = "delete_scope_map")]
    /// Remove a mapping from groups to scopes
    DeleteScopeMap(Oauth2DeleteScopeMapOpt),
    #[clap(name = "reset_secrets")]
    /// Reset the secrets associated to this resource server
    ResetSecrets(Named),
    #[clap(name = "delete")]
    /// Delete a oauth2 resource server
    Delete(Named),
    /// Set a new displayname for a resource server
    #[clap(name = "set_displayname")]
    SetDisplayname(Oauth2SetDisplayname),
    #[clap(name = "enable_pkce")]
    /// Enable PKCE on this oauth2 resource server. This defaults to being enabled.
    EnablePkce(Named),
    /// Disable PKCE on this oauth2 resource server to work around insecure clients that
    /// may not support it. You should request the client to enable PKCE!
    #[clap(name = "warning_insecure_client_disable_pkce")]
    DisablePkce(Named),
    #[clap(name = "warning_enable_legacy_crypto")]
    /// Enable legacy signing crypto on this oauth2 resource server. This defaults to being disabled.
    /// You only need to enable this for openid clients that do not support modern crytopgraphic
    /// operations.
    EnableLegacyCrypto(Named),
    /// Disable legacy signing crypto on this oauth2 resource server. This is the default.
    #[clap(name = "disable_legacy_crypto")]
    DisableLegacyCrypto(Named),
}

#[derive(Args, Debug)]
pub struct OptSetDomainDisplayName{
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "new_display_Name")]
    new_display_name: String,
}

#[derive(Debug, Subcommand)]
pub enum DomainOpt {
    #[clap[name = "set_domain_display_name"]]
    /// Set the domain display name
    SetDomainDisplayName(OptSetDomainDisplayName),
    #[clap(name = "show")]
    /// Show information about this system's domain
    Show(CommonOpt),
    #[clap(name = "reset_token_key")]
    /// Reset this domain token signing key. This will cause all user sessions to be
    /// invalidated (logged out).
    ResetTokenKey(CommonOpt),
}

#[derive(Debug, Subcommand)]
pub enum SystemOpt {
    #[clap(name = "oauth2")]
    /// Configure and display oauth2/oidc resource server configuration
    Oauth2 {
        #[clap(subcommand)]
        commands: Oauth2Opt,
    },
    #[clap(name = "domain")]
    /// Configure and display domain configuration
    Domain {
        #[clap(subcommand)]
        commands: DomainOpt,
    },
}

#[derive(Debug, Subcommand)]
#[clap(about = "Kanidm Client Utility")]
pub enum KanidmClientOpt {
    /// Login to an account to use with future cli operations
    Login(LoginOpt),
    /// Logout of an active cli session
    Logout(LogoutOpt),
    /// Manage active cli sessions
    Session {
        #[clap(subcommand)]
        commands: SessionOpt,
    },
    #[clap(name = "self")]
    /// Actions for the current authenticated account
    CSelf {
        #[clap(subcommand)]
        commands: SelfOpt,
    },
    /// Account operations
    Account {
        #[clap(subcommand)]
        commands: AccountOpt,
    },
    /// Group operations
    Group {
        #[clap(subcommand)]
        commands: GroupOpt,
    },
    /// System configuration operations
    System {
        #[clap(subcommand)]
        commands: SystemOpt,
    },
    #[clap(name = "recycle_bin")]
    /// Recycle Bin operations
    Recycle {
        #[clap(subcommand)]
        commands: RecycleOpt,
    },
    /// Unsafe - low level, raw database operations.
    Raw {
        #[clap(subcommand)]
        commands: RawOpt,
    },
    /// Print the program version and exit
    Version {

    }
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Kanidm Client Utility")]
pub struct KanidmClientParser {
    #[clap(subcommand)]
    pub commands: KanidmClientOpt,
}
