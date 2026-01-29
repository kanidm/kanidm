#[derive(Debug, Args)]
struct BackupOpt {
    #[clap(value_parser)]
    /// Output path for the backup content.
    path: PathBuf,

    /// Compression method
    #[clap(short = 'C', long, env = "KANIDM_BACKUP_COMPRESSION")]
    compression: Option<String>,
}

#[derive(Debug, Args)]
struct RestoreOpt {
    #[clap(value_parser)]
    /// Restore from this path. Should be created with "backup".
    path: PathBuf,
}

#[derive(Debug, Subcommand)]
enum DomainSettingsCmds {
    /// Show the current domain
    #[clap(name = "show")]
    Show,
    /// Change the IDM domain name based on the values in the configuration
    #[clap(name = "rename")]
    Change,
    /// Perform a pre-upgrade-check of this domains content. This will report possible
    /// incompatibilities that can block a successful upgrade to the next version of
    /// Kanidm. This is a safe read only operation.
    #[clap(name = "upgrade-check")]
    UpgradeCheck,
    /// ⚠️  Do not use this command unless directed by a project member. ⚠️
    /// - Raise the functional level of this domain to the maximum available.
    #[clap(name = "raise")]
    Raise,
    /// ⚠️  Do not use this command unless directed by a project member. ⚠️
    /// - Rerun migrations of this domains database, optionally nominating the level
    ///   to start from.
    #[clap(name = "remigrate")]
    Remigrate { level: Option<u32> },
}

#[derive(Debug, Subcommand)]
enum DbCommands {
    #[clap(name = "vacuum")]
    /// Vacuum the database to reclaim space or change db_fs_type/page_size (offline)
    Vacuum,
    #[clap(name = "backup")]
    /// Backup the database content (offline)
    Backup(BackupOpt),
    #[clap(name = "restore")]
    /// Restore the database content (offline)
    Restore(RestoreOpt),
    #[clap(name = "verify")]
    /// Verify database and entity consistency.
    Verify,
    #[clap(name = "reindex")]
    /// Reindex the database (offline)
    Reindex,
}

#[derive(Debug, Args)]
struct DbScanListIndex {
    /// The name of the index to list
    index_name: String,
}

#[derive(Debug, Args)]
struct DbScanGetId2Entry {
    /// The id of the entry to display
    id: u64,
}

#[derive(Debug, Subcommand)]
enum DbScanOpt {
    #[clap(name = "list-all-indexes")]
    /// List all index tables that exist on the system.
    ListIndexes,
    #[clap(name = "list-index")]
    /// List all content of a named index
    ListIndex(DbScanListIndex),
    // #[structopt(name = "get_index")]
    // /// Display the content of a single index key
    // GetIndex(DbScanGetIndex),
    #[clap(name = "list-id2entry")]
    /// List all id2entry values with reduced entry content
    ListId2Entry,
    #[clap(name = "get-id2entry")]
    /// View the data of a specific entry from id2entry
    GetId2Entry(DbScanGetId2Entry),
    #[clap(name = "list-index-analysis")]
    /// List all content of index analysis
    ListIndexAnalysis,
    #[clap(name = "quarantine-id2entry")]
    /// Given an entry id, quarantine the entry in a hidden db partition
    QuarantineId2Entry {
        /// The id of the entry to display
        id: u64,
    },
    #[clap(name = "list-quarantined")]
    /// List the entries in quarantine
    ListQuarantined,
    #[clap(name = "restore-quarantined")]
    /// Given an entry id, restore the entry from the hidden db partition
    RestoreQuarantined {
        /// The id of the entry to display
        id: u64,
    },
}

#[derive(Debug, Parser)]
#[command(name = "kanidmd")]
struct KanidmdParser {
    #[command(subcommand)]
    commands: KanidmdOpt,

    #[clap(short, long, env = "KANIDM_CONFIG", global = true)]
    config_path: Option<PathBuf>,

    #[clap(flatten)]
    kanidmd_options: kanidm_proto::cli::KanidmdCli,
}

#[derive(Debug, Subcommand)]
enum ScriptingCommand {
    /// Recover an account's password
    RecoverAccount {
        #[clap(value_parser)]
        /// The account name to recover credentials for.
        name: String,
    },
    /// Backup
    Backup {
        /// The path to backup to. If not set, defaults to stdout.
        path: Option<PathBuf>
    },
    /// Initiate a server reload.
    Reload,
    /// Load the server config and check services are listening
    #[clap(name = "healthcheck")]
    HealthCheck {
        /// Disable TLS verification
        #[clap(short, long, action)]
        verify_tls: bool,
        /// Check the 'origin' URL from the server configuration file, instead of the 'address'
        #[clap(short = 'O', long, action)]
        check_origin: bool,
    }
}

// The main command parser for kanidmd
#[derive(Debug, Subcommand)]
enum KanidmdOpt {
    #[clap(name = "server")]
    /// Start the IDM Server
    Server,
    #[clap(name = "configtest")]
    /// Test the IDM Server configuration, without starting network listeners.
    ConfigTest,
    #[clap(name = "cert-generate")]
    /// Create a self-signed ca and tls certificate in the locations listed from the
    /// configuration. These certificates should *not* be used in production, they
    /// are for testing and evaluation only!
    CertGenerate,
    #[clap(name = "recover-account")]
    /// Recover an account's password
    RecoverAccount {
        #[clap(value_parser)]
        /// The account name to recover credentials for.
        name: String,
    },
    #[clap(name = "disable-account")]
    /// Disable an account so that it can not be used. This can be reset with `recover-account`.
    DisableAccount {
        #[clap(value_parser)]
        /// The account name to disable.
        name: String,
    },
    /// Display this server's replication certificate
    ShowReplicationCertificate,
    /// Renew this server's replication certificate
    RenewReplicationCertificate,
    /// Refresh this servers database content with the content from a supplier. This means
    /// that all local content will be deleted and replaced with the supplier content.
    RefreshReplicationConsumer {
        /// Acknowledge that this database content will be refreshed from a supplier.
        #[clap(long = "i-want-to-refresh-this-servers-database")]
        proceed: bool,
    },
    // #[clap(name = "reset_server_id")]
    // ResetServerId,
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

    /// Print the program version and exit
    #[clap(name = "version")]
    Version,

    /// A dedicated scripting interface that has machine parsable input/outputs.
    #[clap(name = "scripting")]
    Scripting {
        #[clap(subcommand)]
        command: ScriptingCommand
    }
}
