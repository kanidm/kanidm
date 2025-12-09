use crate::internal::FsType;
use clap::Parser;

#[derive(Debug, Parser, Clone)]
pub struct KanidmdCli {
    /// Output formatting
    #[clap(
        short,
        long = "output",
        env = "KANIDM_OUTPUT",
        default_value = "text",
        global = true,
        help = "Specify the console output format (text, json)"
    )]
    pub output_mode: crate::messages::ConsoleOutputMode,

    #[clap(
        env = "KANIDM_LOG_LEVEL",
        global = true,
        help = "Specify the log level (info, debug, trace)"
    )]
    pub log_level: Option<sketching::LogLevel>,

    #[clap(
        env = "KANIDM_OTEL_GRPC_URL",
        global = true,
        help = "Specify the OpenTelemetry gRPC URL"
    )]
    pub otel_grpc_url: Option<String>,

    #[clap(env = "KANIDM_DOMAIN", global = true, help = "Specify the domain")]
    pub domain: Option<String>,

    #[clap(env = "KANIDM_ORIGIN", global = true, help = "Specify the origin URL")]
    pub origin: Option<url::Url>,

    #[clap(env = "KANIDM_ROLE", global = true, help = "Specify the server role")]
    pub role: Option<crate::config::ServerRole>,

    #[clap(
        env = "KANIDM_DB_PATH",
        global = true,
        help = "Specify the database path"
    )]
    pub db_path: Option<std::path::PathBuf>,

    #[clap(
        env = "KANIDM_DB_FS_TYPE",
        global = true,
        help = "Specify the database filesystem type, either zfs or generic"
    )]
    pub db_fs_type: Option<FsType>,

    #[clap(
        env = "KANIDM_DB_ARC_SIZE",
        global = true,
        help = "Specify the database ARC size in bytes"
    )]
    pub db_arc_size: Option<usize>,

    #[clap(
        env = "KANIDM_SERVER_ADMIN_BIND_PATH",
        global = true,
        help = "Specify the admin bind path"
    )]
    pub admin_bind_path: Option<String>,

    // TLS
    #[clap(
        env = "KANIDM_TLS_CHAIN",
        global = true,
        help = "Specify the TLS chain file path"
    )]
    pub tls_chain: Option<std::path::PathBuf>,
    #[clap(
        env = "KANIDM_TLS_KEY",
        global = true,
        help = "Specify the TLS key file path"
    )]
    pub tls_key: Option<std::path::PathBuf>,

    #[clap(
        env = "KANIDM_TLS_CLIENT_CA",
        global = true,
        help = "Specify the TLS client CA file path"
    )]
    pub tls_client_ca: Option<std::path::PathBuf>,

    // networking
    #[clap(
        env = "KANIDM_BINDADDRESS",
        global = true,
        help = "Specify the HTTPS server bind address(es)"
    )]
    pub bindaddress: Option<String>,

    #[clap(
        env = "KANIDM_LDAPBINDADDRESS",
        global = true,
        help = "Specify the LDAP bind address(es)"
    )]
    pub ldapbindaddress: Option<String>,

    #[clap(
        global = true,
        hide = true,
        env = "KANIDM_TRUST_X_FORWARDED_FOR",
        help = "Whether to blindly trust the X-Forwarded-For header, regardless of source IP"
    )]
    pub trust_all_x_forwarded_for: Option<bool>,

    // replication
    #[clap(
        env = "KANIDM_REPLICATION_ORIGIN",
        global = true,
        help = "Specify the replication origin URL"
    )]
    pub replication_origin: Option<url::Url>,

    #[clap(
        env = "KANIDM_REPLICATION_BINDADDRESS",
        global = true,
        help = "Specify the replication bind address"
    )]
    pub replication_bindaddress: Option<std::net::SocketAddr>,

    #[clap(
        env = "KANIDM_REPLICATION_TASK_POLL_INTERVAL",
        global = true,
        help = "Specify the replication task poll interval in seconds"
    )]
    pub replication_task_poll_interval: Option<u64>,

    // backup things
    #[clap(
        env = "KANIDM_ONLINE_BACKUP_PATH",
        global = true,
        help = "Specify the online backup path"
    )]
    pub online_backup_path: Option<std::path::PathBuf>,

    #[clap(
        global = true,
        env = "KANIDM_ONLINE_BACKUP_VERSIONS",
        help = "Number of online backup versions to keep"
    )]
    pub online_backup_versions: Option<usize>,

    #[clap(
        global = true,
        env = "KANIDM_ONLINE_BACKUP_SCHEDULE",
        help = "Cron schedule for online backups",
        last = true
    )]
    pub online_backup_schedule: Option<String>,
}
