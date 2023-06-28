#[derive(Debug, Args)]
struct CommonOpt {
    #[clap(parse(from_os_str), default_value = "", short, long = "config", env = "KANIDM_CONFIG")]
    /// Path to the server's configuration file. If it does not exist, it will be created.
    config_path: PathBuf,
    /// Log format (still in very early development)
    #[clap(short, long = "output", env = "KANIDM_OUTPUT", default_value="text")]
    output_mode: String,
}

#[derive(Debug, Args)]
struct BackupOpt {
    #[clap(parse(from_os_str))]
    /// Output path for the backup content.
    path: PathBuf,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Args)]
struct RestoreOpt {
    #[clap(parse(from_os_str))]
    /// Restore from this path. Should be created with "backup".
    path: PathBuf,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Args)]
struct RecoverAccountOpt {
    #[clap(value_parser)]
    /// The account name to recover credentials for.
    name: String,
    #[clap(flatten)]
    commonopts: CommonOpt,
}


#[derive(Debug, Subcommand)]
enum DomainSettingsCmds {
    #[clap(name = "rename")]
    /// Change the IDM domain name
    DomainChange(CommonOpt),
}

#[derive(Debug, Subcommand)]
enum DbCommands {
    #[clap(name = "vacuum")]
    /// Vacuum the database to reclaim space or change db_fs_type/page_size (offline)
    Vacuum(CommonOpt),
    #[clap(name = "backup")]
    /// Backup the database content (offline)
    Backup(BackupOpt),
    #[clap(name = "restore")]
    /// Restore the database content (offline)
    Restore(RestoreOpt),
    #[clap(name = "verify")]
    /// Verify database and entity consistency.
    Verify(CommonOpt),
    #[clap(name = "reindex")]
    /// Reindex the database (offline)
    Reindex(CommonOpt),
}

#[derive(Debug, Args)]
struct DbScanListIndex {
    /// The name of the index to list
    index_name: String,
    #[clap(flatten)]
    commonopts: CommonOpt,
}


#[derive(Debug,Parser)]
struct HealthCheckArgs {
    /// Disable TLS verification
    #[clap(short, long, action)]
    verify_tls: bool,
    /// Check the 'origin' URL from the server configuration file, instead of the 'address'
    #[clap(short='O', long, action)]
    check_origin: bool,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

/*
#[derive(Debug, Args)]
struct DbScanGetIndex {
    /// The name of the index to list
    index_name: String,
    /// The name of the index key to retrieve
    key: String,
    #[clap(flatten)]
    commonopts: CommonOpt,
}
*/

#[derive(Debug, Args)]
struct DbScanGetId2Entry {
    /// The id of the entry to display
    id: u64,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Subcommand)]
enum DbScanOpt {
    #[clap(name = "list-all-indexes")]
    /// List all index tables that exist on the system.
    ListIndexes(CommonOpt),
    #[clap(name = "list-index")]
    /// List all content of a named index
    ListIndex(DbScanListIndex),
    // #[structopt(name = "get_index")]
    // /// Display the content of a single index key
    // GetIndex(DbScanGetIndex),
    #[clap(name = "list-id2entry")]
    /// List all id2entry values with reduced entry content
    ListId2Entry(CommonOpt),
    #[clap(name = "get-id2entry")]
    /// View the data of a specific entry from id2entry
    GetId2Entry(DbScanGetId2Entry),
    #[clap(name = "list-index-analysis")]
    /// List all content of index analysis
    ListIndexAnalysis(CommonOpt),
}

#[derive(Debug, Parser)]
struct KanidmdParser {
    #[clap(subcommand)]
    commands: KanidmdOpt,
}

#[derive(Debug, Subcommand)]
enum KanidmdOpt {
    #[clap(name = "server")]
    /// Start the IDM Server
    Server(CommonOpt),
    #[clap(name = "configtest")]
    /// Test the IDM Server configuration, without starting network listeners.
    ConfigTest(CommonOpt),
    #[clap(name = "cert-generate")]
    /// Create a self-signed ca and tls certificate in the locations listed from the
    /// configuration. These certificates should *not* be used in production, they
    /// are for testing and evaluation only!
    CertGenerate(CommonOpt),
    #[clap(name = "recover-account")]
    /// Recover an account's password
    RecoverAccount(RecoverAccountOpt),
    // #[clap(name = "reset_server_id")]
    // ResetServerId(CommonOpt),
    #[clap(name = "db-scan")]
    /// Inspect the internal content of the database datastructures.
    DbScan {
        #[clap(subcommand)]
        commands: DbScanOpt,
    },
    /// Database maintenance, backups, restoration etc.
    #[clap(name = "database")]
    Database {
        #[clap(subcommand)]
        commands: DbCommands,
    },
    /// Change domain settings
    #[clap(name = "domain")]
    DomainSettings {
        #[clap(subcommand)]
        commands: DomainSettingsCmds,
    },
    /// Load the server config and check services are listening
    #[clap(name = "healthcheck")]
    HealthCheck(HealthCheckArgs),

    /// Print the program version and exit
    #[clap(name="version")]
    Version(CommonOpt)
}
