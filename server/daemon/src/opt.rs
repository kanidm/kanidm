#[derive(Debug, Args)]
struct CommonOpt {
    /// Path to the server's configuration file.
    #[clap(short, long = "config", env = "KANIDM_CONFIG")]
    config_path: Option<PathBuf>,
    /// Log format (still in very early development)
    #[clap(short, long = "output", env = "KANIDM_OUTPUT", default_value = "text")]
    output_mode: String,
}

#[derive(Debug, Args)]
struct BackupOpt {
    #[clap(value_parser)]
    /// Output path for the backup content.
    path: PathBuf,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Args)]
struct RestoreOpt {
    #[clap(value_parser)]
    /// Restore from this path. Should be created with "backup".
    path: PathBuf,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Subcommand)]
enum DomainSettingsCmds {
    #[clap(name = "show")]
    /// Show the current domain
    Show {
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    #[clap(name = "rename")]
    /// Change the IDM domain name based on the values in the configuration
    Change {
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    #[clap(name = "raise")]
    /// Raise the functional level of this domain to the maximum available.
    Raise {
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    #[clap(name = "remigrate")]
    /// Rerun migrations of this domains database, optionally nominating the level
    /// to start from.
    Remigrate {
        #[clap(flatten)]
        commonopts: CommonOpt,
        level: Option<u32>,
    },
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

#[derive(Debug, Parser)]
struct HealthCheckArgs {
    /// Disable TLS verification
    #[clap(short, long, action)]
    verify_tls: bool,
    /// Check the 'origin' URL from the server configuration file, instead of the 'address'
    #[clap(short = 'O', long, action)]
    check_origin: bool,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

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
    #[clap(name = "quarantine-id2entry")]
    /// Given an entry id, quarantine the entry in a hidden db partition
    QuarantineId2Entry {
        /// The id of the entry to display
        id: u64,
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    #[clap(name = "list-quarantined")]
    /// List the entries in quarantine
    ListQuarantined {
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    #[clap(name = "restore-quarantined")]
    /// Given an entry id, restore the entry from the hidden db partition
    RestoreQuarantined {
        /// The id of the entry to display
        id: u64,
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
}

#[derive(Debug, Parser)]
#[command(name = "kanidmd")]
struct KanidmdParser {
    #[command(subcommand)]
    commands: KanidmdOpt,
}

impl KanidmdParser {
    /// Returns the configuration path that was specified on the command line, if any.
    fn config_path(&self) -> Option<PathBuf> {
        match self.commands {
            KanidmdOpt::Server(ref c) => c.config_path.clone(),
            KanidmdOpt::ConfigTest(ref c) => c.config_path.clone(),
            KanidmdOpt::CertGenerate(ref c) => c.config_path.clone(),
            KanidmdOpt::RecoverAccount { ref commonopts, .. } => commonopts.config_path.clone(),
            KanidmdOpt::ShowReplicationCertificate { ref commonopts, .. } => {
                commonopts.config_path.clone()
            }
            KanidmdOpt::RenewReplicationCertificate { ref commonopts, .. } => {
                commonopts.config_path.clone()
            }
            KanidmdOpt::RefreshReplicationConsumer { ref commonopts, .. } => {
                commonopts.config_path.clone()
            }
            KanidmdOpt::DbScan { ref commands } => match commands {
                DbScanOpt::ListIndexes(ref c) => c.config_path.clone(),
                DbScanOpt::ListIndex(ref c) => c.commonopts.config_path.clone(),
                DbScanOpt::ListId2Entry(ref c) => c.config_path.clone(),
                DbScanOpt::GetId2Entry(ref c) => c.commonopts.config_path.clone(),
                DbScanOpt::ListIndexAnalysis(ref c) => c.config_path.clone(),
                DbScanOpt::QuarantineId2Entry { ref commonopts, .. } => {
                    commonopts.config_path.clone()
                }
                DbScanOpt::ListQuarantined { ref commonopts } => commonopts.config_path.clone(),
                DbScanOpt::RestoreQuarantined { ref commonopts, .. } => {
                    commonopts.config_path.clone()
                }
            },
            KanidmdOpt::Database { ref commands } => match commands {
                DbCommands::Vacuum(ref c) => c.config_path.clone(),
                DbCommands::Backup(ref c) => c.commonopts.config_path.clone(),
                DbCommands::Restore(ref c) => c.commonopts.config_path.clone(),
                DbCommands::Verify(ref c) => c.config_path.clone(),
                DbCommands::Reindex(ref c) => c.config_path.clone(),
            },
            KanidmdOpt::DomainSettings { ref commands } => match commands {
                DomainSettingsCmds::Show { ref commonopts } => commonopts.config_path.clone(),
                DomainSettingsCmds::Change { ref commonopts } => commonopts.config_path.clone(),
                DomainSettingsCmds::Raise { ref commonopts } => commonopts.config_path.clone(),
                DomainSettingsCmds::Remigrate { ref commonopts, .. } => {
                    commonopts.config_path.clone()
                }
            },
            KanidmdOpt::HealthCheck(ref c) => c.commonopts.config_path.clone(),
            KanidmdOpt::Version(ref c) => c.config_path.clone(),
        }
    }
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
    RecoverAccount {
        #[clap(value_parser)]
        /// The account name to recover credentials for.
        name: String,
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    /// Display this server's replication certificate
    ShowReplicationCertificate {
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    /// Renew this server's replication certificate
    RenewReplicationCertificate {
        #[clap(flatten)]
        commonopts: CommonOpt,
    },
    /// Refresh this servers database content with the content from a supplier. This means
    /// that all local content will be deleted and replaced with the supplier content.
    RefreshReplicationConsumer {
        #[clap(flatten)]
        commonopts: CommonOpt,
        /// Acknowledge that this database content will be refreshed from a supplier.
        #[clap(long = "i-want-to-refresh-this-servers-database")]
        proceed: bool,
    },
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
    #[clap(name = "version")]
    Version(CommonOpt),
}
