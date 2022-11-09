

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

    #[clap(short, long, hide = true)]
    /// Dump the ldap protocol inputs, as well as the scim outputs. This can be used
    /// to create test cases for testing the parser.
    ///
    /// No actions are taken on the kanidm instance, this is purely a dump of the
    /// state in/out.
    pub proto_dump: bool,

    #[clap(short, long, hide = true)]
    pub skip_root_check: bool,
}
