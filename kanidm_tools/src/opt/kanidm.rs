#[derive(Debug, StructOpt)]
pub struct Named {
    #[structopt()]
    pub name: String,
    #[structopt(flatten)]
    pub copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    pub debug: bool,
    #[structopt(short = "H", long = "url")]
    pub addr: Option<String>,
    #[structopt(short = "D", long = "name")]
    pub username: Option<String>,
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
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
pub struct AccountNamedTagPKOpt {
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
    #[structopt(name = "set_password")]
    SetPassword(AccountCredentialSet),
    #[structopt(name = "generate_password")]
    GeneratePassword(AccountCredentialSet),
    #[structopt(name = "register_webauthn")]
    RegisterWebauthn(AccountNamedTagOpt),
    /// Set the TOTP credential of the account. If a TOTP already exists, on a successful
    /// registration, this will replace it.
    #[structopt(name = "set_totp")]
    RegisterTOTP(AccountNamedTagOpt),
    /// Remove TOTP from the account. If no TOTP exists, no action is taken.
    #[structopt(name = "remove_totp")]
    RemoveTOTP(AccountNamedOpt),
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
    Add(AccountNamedTagPKOpt),
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
#[structopt(about = "Kanidm Client Utility")]
pub enum KanidmClientOpt {
    #[structopt(name = "login")]
    /// Login to an account to use with future cli operations
    Login(LoginOpt),
    #[structopt(name = "self")]
    /// Actions for the current authenticated account
    CSelf(SelfOpt),
    #[structopt(name = "account")]
    /// Account operations
    Account(AccountOpt),
    #[structopt(name = "group")]
    /// Group operations
    Group(GroupOpt),
    #[structopt(name = "recycle_bin")]
    /// Recycle Bin operations
    Recycle(RecycleOpt),
    #[structopt(name = "raw")]
    /// Unsafe - low level, raw database operations.
    Raw(RawOpt),
}

