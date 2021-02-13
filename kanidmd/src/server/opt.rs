#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    /// Logging level. quiet, default, filter, verbose, perffull
    debug: Option<LogLevel>,
    #[structopt(parse(from_os_str), short = "c", long = "config")]
    /// Path to the server's configuration file. If it does not exist, it will be created.
    config_path: PathBuf,
}

#[derive(Debug, StructOpt)]
struct BackupOpt {
    #[structopt(parse(from_os_str))]
    /// Output path for the backup content.
    path: PathBuf,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct RestoreOpt {
    #[structopt(parse(from_os_str))]
    /// Restore from this path. Should be created with "backupu".
    path: PathBuf,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct RecoverAccountOpt {
    #[structopt(short)]
    /// The account name to recover credentials for.
    name: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct DomainOpt {
    #[structopt(short)]
    /// The new domain name.
    new_domain_name: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum KanidmdOpt {
    #[structopt(name = "server")]
    /// Start the IDM Server
    Server(CommonOpt),
    #[structopt(name = "backup")]
    /// Backup the database content (offline)
    Backup(BackupOpt),
    #[structopt(name = "restore")]
    /// Restore the database content (offline)
    Restore(RestoreOpt),
    #[structopt(name = "verify")]
    /// Verify database and entity consistency.
    Verify(CommonOpt),
    #[structopt(name = "recover_account")]
    /// Recover an account's password
    RecoverAccount(RecoverAccountOpt),
    // #[structopt(name = "reset_server_id")]
    // ResetServerId(CommonOpt),
    #[structopt(name = "reindex")]
    /// Reindex the database (offline)
    Reindex(CommonOpt),
    #[structopt(name = "domain_name_change")]
    /// Change the IDM domain name
    DomainChange(DomainOpt),
}

