

use kanidm_proto::constants::DEFAULT_CLIENT_CONFIG_PATH;
pub const DEFAULT_IPA_CONFIG_PATH: &str = "/etc/kanidm/ipa-sync";


#[derive(Debug, clap::Parser)]
#[clap(about = "Kanidm FreeIPA Sync Driver")]
pub struct Opt {
    /// Enable debbuging of the sync driver
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
    /// Path to the client config file.
    #[clap(parse(from_os_str), short, long, default_value_os_t = DEFAULT_CLIENT_CONFIG_PATH.into())]
    pub client_config: PathBuf,

    /// Path to the ipa-sync config file.
    #[clap(parse(from_os_str), short, long, default_value_os_t = DEFAULT_IPA_CONFIG_PATH.into())]
    pub ipa_sync_config: PathBuf,

    /// Dump the ldap protocol inputs, as well as the scim outputs. This can be used
    /// to create test cases for testing the parser.
    ///
    /// No actions are taken on the kanidm instance, this is purely a dump of the
    /// state in/out.
    #[clap(short, long, hide = true)]
    pub proto_dump: bool,

    /// Read entries from ipa, and check the connection to kanidm, but take no actions against
    /// kanidm that would change state.
    #[clap(short = 'n')]
    pub dry_run: bool,

    /// Run in scheduled mode, where the sync tool will periodically attempt to sync between
    /// FreeIPA and Kanidm.
    #[clap(long = "schedule")]
    pub schedule: bool,

    /// Skip the root user permission check.
    #[clap(short, long, hide = true)]
    pub skip_root_check: bool,
}
