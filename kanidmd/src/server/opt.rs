#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug", env = "KANIDM_DEBUG")]
    /// Logging level. quiet, default, filter, verbose, perffull
    debug: Option<LogLevel>,
    #[structopt(parse(from_os_str), short = "c", long = "config", env = "KANIDM_CONFIG")]
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
    /// Restore from this path. Should be created with "backup".
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
struct DbScanListIndex {
    /// The name of the index to list
    index_name: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

/*
#[derive(Debug, StructOpt)]
struct DbScanGetIndex {
    /// The name of the index to list
    index_name: String,
    /// The name of the index key to retrieve
    key: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}
*/

#[derive(Debug, StructOpt)]
struct DbScanGetId2Entry {
    /// The id of the entry to display
    id: u64,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum DbScanOpt {
    #[structopt(name = "list_all_indexes")]
    /// List all index tables that exist on the system.
    ListIndexes(CommonOpt),
    #[structopt(name = "list_index")]
    /// List all content of a named index
    ListIndex(DbScanListIndex),
    // #[structopt(name = "get_index")]
    // /// Display the content of a single index key
    // GetIndex(DbScanGetIndex),
    #[structopt(name = "list_id2entry")]
    /// List all id2entry values with reduced entry content
    ListId2Entry(CommonOpt),
    #[structopt(name = "get_id2entry")]
    /// View the data of a specific entry from id2entry
    GetId2Entry(DbScanGetId2Entry),
    #[structopt(name = "list_index_analysis")]
    /// List all content of index analysis
    ListIndexAnalysis(CommonOpt),
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
    #[structopt(name = "vacuum")]
    /// Vacuum the database to reclaim space or change db_fs_type/page_size (offline)
    Vacuum(CommonOpt),
    #[structopt(name = "domain_name_change")]
    /// Change the IDM domain name
    DomainChange(DomainOpt),
    #[structopt(name = "db_scan")]
    /// Inspect the internal content of the database datastructures.
    DbScan(DbScanOpt),
}

