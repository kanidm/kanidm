use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct Named {
    pub name: String,
    #[clap(flatten)]
    pub copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct DebugOpt {
    /// Enable debbuging of the kanidm tool
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
}

#[derive(Debug, Args)]
pub struct CommonOpt {
    /// Enable debbuging of the kanidm tool
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
    /// The URL of the kanidm instance
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
    /// Show details of a specific posix group
    #[clap(name = "show")]
    Show(Named),
    /// Setup posix group properties, or alter them
    #[clap(name = "set")]
    Set(GroupPosixOpt),
}

#[derive(Debug, Subcommand)]
pub enum GroupOpt {
    /// List all groups
    #[clap(name = "list")]
    List(CommonOpt),
    /// View a specific group
    #[clap(name = "get")]
    Get(Named),
    /// Create a new group
    #[clap(name = "create")]
    Create(Named),
    /// Delete a group
    #[clap(name = "delete")]
    Delete(Named),
    /// List the members of a group
    #[clap(name = "list_members")]
    ListMembers(Named),
    /// Set the exact list of members that this group should contain, removing any not listed in the
    /// set operation.
    #[clap(name = "set_members")]
    SetMembers(GroupNamedMembers),
    /// Delete all members of a group.
    #[clap(name = "purge_members")]
    PurgeMembers(Named),
    /// Add new members to a group
    #[clap(name = "add_members")]
    AddMembers(GroupNamedMembers),
    /// Remove the named members from this group
    #[clap(name = "remove_members")]
    RemoveMembers(GroupNamedMembers),
    /// Manage posix extensions for this group allowing groups to be used on unix/linux systems
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
    /// Show the status of this accounts credentials.
    #[clap(name = "status")]
    Status(AccountNamedOpt),
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
pub enum PersonPosix {
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    #[clap(name = "set")]
    Set(AccountPosixOpt),
    #[clap(name = "set_password")]
    SetPassword(AccountNamedOpt),
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountPosix {
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    #[clap(name = "set")]
    Set(AccountPosixOpt),
}

#[derive(Debug, Args)]
pub struct PersonUpdateOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(long, short, help = "Set the legal name for the person.")]
    legalname: Option<String>,
    #[clap(long, short, help = "Set the account name for the person.")]
    newname: Option<String>,
    #[clap(long, short = 'i', help = "Set the display name for the person.")]
    displayname: Option<String>,
    #[clap(
        long,
        short,
        help = "Set the mail address, can be set multiple times for multiple addresses. The first listed mail address is the 'primary'"
    )]
    mail: Option<Vec<String>>,
    #[clap(flatten)]
    copt: CommonOpt,
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
    /// Show an accounts validity window
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    /// Set an accounts expiry time
    #[clap(name = "expire_at")]
    ExpireAt(AccountNamedExpireDateTimeOpt),
    /// Set an account valid from time
    #[clap(name = "begin_from")]
    BeginFrom(AccountNamedValidDateTimeOpt),
}

#[derive(Debug, Subcommand)]
pub enum AccountUserAuthToken {
    /// Show the status of logged in sessions associated to this account.
    #[clap(name = "status")]
    Status(AccountNamedOpt),
    /// Destroy / revoke a session for this account. Access to the
    /// session (user auth token) is NOT required, only the uuid of the session.
    #[clap(name = "destroy")]
    Destroy {
        #[clap(flatten)]
        aopts: AccountCommonOpt,
        #[clap(flatten)]
        copt: CommonOpt,
        /// The UUID of the token to destroy.
        #[clap(name = "session_id")]
        session_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
pub enum PersonOpt {
    /// Manage the credentials this person uses for authentication
    #[clap(name = "credential")]
    Credential {
        #[clap(subcommand)]
        commands: AccountCredential,
    },
    /// Manage radius access for this person
    #[clap(name = "radius")]
    Radius {
        #[clap(subcommand)]
        commands: AccountRadius,
    },
    /// Manage posix extensions for this person allowing access to unix/linux systems
    #[clap(name = "posix")]
    Posix {
        #[clap(subcommand)]
        commands: PersonPosix,
    },
    /// Manage sessions (user auth tokens) associated to this person.
    #[clap(name = "session")]
    Session {
        #[clap(subcommand)]
        commands: AccountUserAuthToken,
    },
    /// Manage ssh public key's associated to this person
    #[clap(name = "ssh")]
    Ssh {
        #[clap(subcommand)]
        commands: AccountSsh,
    },
    /// List all persons
    #[clap(name = "list")]
    List(CommonOpt),
    /// View a specific person
    #[clap(name = "get")]
    Get(AccountNamedOpt),
    /// Update a specific person's attributes
    #[clap(name = "update")]
    Update(PersonUpdateOpt),
    /// Create a new person's account
    #[clap(name = "create")]
    Create(AccountCreateOpt),
    /// Delete a person's account
    #[clap(name = "delete")]
    Delete(AccountNamedOpt),
    /// Manage a person's account validity, such as expiry time (account lock/unlock)
    #[clap(name = "validity")]
    Validity {
        #[clap(subcommand)]
        commands: AccountValidity,
    },
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountCredential {
    /// Show the status of this accounts password
    #[clap(name = "status")]
    Status(AccountNamedOpt),
    /// Reset and generate a new service account password. This password can NOT
    /// be used with the LDAP interface.
    #[clap(name = "generate")]
    GeneratePw(AccountNamedOpt),
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountApiToken {
    /// Show the status of api tokens associated to this service account.
    #[clap(name = "status")]
    Status(AccountNamedOpt),
    /// Generate a new api token for this service account.
    #[clap(name = "generate")]
    Generate {
        #[clap(flatten)]
        aopts: AccountCommonOpt,
        #[clap(flatten)]
        copt: CommonOpt,
        /// A string describing the token. This is not used to identify the token, it is only
        /// for human description of the tokens purpose.
        #[clap(name = "label")]
        label: String,
        #[clap(name = "expiry")]
        /// An optional rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00".
        /// After this time the api token will no longer be valid.
        expiry: Option<String>,
        #[clap(long = "rw")]
        read_write: bool,
    },
    /// Destroy / revoke an api token from this service account. Access to the
    /// token is NOT required, only the tag/uuid of the token.
    #[clap(name = "destroy")]
    Destroy {
        #[clap(flatten)]
        aopts: AccountCommonOpt,
        #[clap(flatten)]
        copt: CommonOpt,
        /// The UUID of the token to destroy.
        #[clap(name = "token_id")]
        token_id: Uuid,
    },
}

#[derive(Debug, Args)]
pub struct ServiceAccountUpdateOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(long, short, help = "Set the account name for the service account.")]
    newname: Option<String>,
    #[clap(
        long,
        short = 'i',
        help = "Set the display name for the service account."
    )]
    displayname: Option<String>,
    #[clap(
        long,
        short,
        help = "Set the mail address, can be set multiple times for multiple addresses. The first listed mail address is the 'primary'"
    )]
    mail: Option<Vec<String>>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountOpt {
    /// Manage the generated password of this service account.
    #[clap(name = "credential")]
    Credential {
        #[clap(subcommand)]
        commands: ServiceAccountCredential,
    },
    /// Manage api tokens associated to this service account.
    #[clap(name = "api-token")]
    ApiToken {
        #[clap(subcommand)]
        commands: ServiceAccountApiToken,
    },
    /// Manage posix extensions for this service account allowing access to unix/linux systems
    #[clap(name = "posix")]
    Posix {
        #[clap(subcommand)]
        commands: ServiceAccountPosix,
    },
    /// Manage sessions (user auth tokens) associated to this service account.
    #[clap(name = "session")]
    Session {
        #[clap(subcommand)]
        commands: AccountUserAuthToken,
    },
    /// Manage ssh public key's associated to this person
    #[clap(name = "ssh")]
    Ssh {
        #[clap(subcommand)]
        commands: AccountSsh,
    },
    /// List all service accounts
    #[clap(name = "list")]
    List(CommonOpt),
    /// View a specific service account
    #[clap(name = "get")]
    Get(AccountNamedOpt),
    /// Create a new service account
    #[clap(name = "create")]
    Create(AccountCreateOpt),
    /// Update a specific service account's attributes
    #[clap(name = "update")]
    Update(ServiceAccountUpdateOpt),
    /// Delete a service account
    #[clap(name = "delete")]
    Delete(AccountNamedOpt),
    /// Manage a service account validity, such as expiry time (account lock/unlock)
    #[clap(name = "validity")]
    Validity {
        #[clap(subcommand)]
        commands: AccountValidity,
    },
    /// Convert a service account into a person. This is used during the alpha.9
    /// to alpha.10 migration to "fix up" accounts that were not previously marked
    /// as persons.
    #[clap(name = "into-person")]
    IntoPerson(AccountNamedOpt),
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
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(short, long, hide = true)]
    /// Do not send the logout to the server - only remove the session token locally
    local_only: bool,
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
    #[clap(name = "update_scope_map", visible_aliases=&["create_scope_map"])]
    /// Update or add a new mapping from a group to scopes that it provides to members
    UpdateScopeMap(Oauth2CreateScopeMapOpt),
    #[clap(name = "delete_scope_map")]
    /// Remove a mapping from groups to scopes
    DeleteScopeMap(Oauth2DeleteScopeMapOpt),

    #[clap(name = "update_sup_scope_map", visible_aliases=&["create_sup_scope_map"])]
    /// Update or add a new mapping from a group to scopes that it provides to members
    UpdateSupScopeMap(Oauth2CreateScopeMapOpt),
    #[clap(name = "delete_sup_scope_map")]
    /// Remove a mapping from groups to scopes
    DeleteSupScopeMap(Oauth2DeleteScopeMapOpt),

    #[clap(name = "reset_secrets")]
    /// Reset the secrets associated to this resource server
    ResetSecrets(Named),
    #[clap(name = "show_basic_secret")]
    /// Show the associated basic secret for this resource server
    ShowBasicSecret(Named),
    #[clap(name = "delete")]
    /// Delete a oauth2 resource server
    Delete(Named),
    /// Set a new displayname for a resource server
    #[clap(name = "set_displayname")]
    SetDisplayname(Oauth2SetDisplayname),
    /// Set a new name for this resource server. You may need to update
    /// your integrated applications after this so that they continue to
    /// function correctly.
    #[clap(name = "set_name")]
    SetName {
        #[clap(flatten)]
        nopt: Named,
        #[clap(name = "newname")]
        name: String,
    },
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
    #[clap(name = "prefer_short_username")]
    /// Use the 'name' attribute instead of 'spn' for the preferred_username
    PreferShortUsername(Named),
    #[clap(name = "prefer_spn_username")]
    /// Use the 'spn' attribute instead of 'name' for the preferred_username
    PreferSPNUsername(Named),
}

#[derive(Args, Debug)]
pub struct OptSetDomainDisplayName {
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "new_display_Name")]
    new_display_name: String,
}


#[derive(Debug, Subcommand)]
pub enum PwBadlistOpt {
    #[clap[name = "show"]]
    /// Show information about this system's password badlist
    Show(CommonOpt),
    #[clap[name = "upload"]]
    /// Upload an extra badlist, appending to the currently configured one.
    /// This badlist will be preprocessed to remove items that are already
    /// caught by "zxcvbn" at the configured level.
    Upload {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(parse(from_os_str))]
        paths: Vec<PathBuf>,
    },
    #[clap[name = "remove", hide = true]]
    /// Remove the content of these lists if present in the configured
    /// badlist.
    Remove {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(parse(from_os_str))]
        paths: Vec<PathBuf>,
    }
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
pub enum SynchOpt {
    #[clap(name = "list")]
    /// List all configured IDM sync accounts
    List(CommonOpt),
    #[clap(name = "get")]
    /// Display a selected IDM sync account
    Get(Named),
    /// Create a new IDM sync account
    #[clap(name = "create")]
    Create {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "description")]
        description: Option<String>,
    },
    #[clap(name = "generate-token")]
    GenerateToken {
        #[clap()]
        account_id: String,
        #[clap()]
        label: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    #[clap(name = "destroy-token")]
    DestroyToken {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
}

#[derive(Debug, Subcommand)]
pub enum SystemOpt {
    #[clap(name = "pw-badlist")]
    /// Configure and manage the password badlist entry
    PwBadlist {
        #[clap(subcommand)]
        commands: PwBadlistOpt,
    },
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
    #[clap(name = "sync", hide = true)]
    Synch {
        #[clap(subcommand)]
        commands: SynchOpt,
    }
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
    /// Actions to manage and view person (user) accounts
    Person {
        #[clap(subcommand)]
        commands: PersonOpt,
    },
    /// Actions to manage groups
    Group {
        #[clap(subcommand)]
        commands: GroupOpt,
    },
    /// Actions to manage and view service accounts
    #[clap(name = "service-account")]
    ServiceAccount {
        #[clap(subcommand)]
        commands: ServiceAccountOpt,
    },
    /// System configuration operations
    System {
        #[clap(subcommand)]
        commands: SystemOpt,
    },
    #[clap(name = "recycle-bin")]
    /// Recycle Bin operations
    Recycle {
        #[clap(subcommand)]
        commands: RecycleOpt,
    },
    /// Unsafe - low level, raw database queries and operations.
    #[clap(hide = true)]
    Raw {
        #[clap(subcommand)]
        commands: RawOpt,
    },
    /// Print the program version and exit
    Version {},
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Kanidm Client Utility")]
pub struct KanidmClientParser {
    #[clap(subcommand)]
    pub commands: KanidmClientOpt,
}
