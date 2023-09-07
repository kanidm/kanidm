use std::str::FromStr;

#[derive(Debug, Parser)]
struct CommonOpt {
    #[clap(short, long)]
    /// Enable debug logging
    pub debug: bool,
}

#[derive(Debug, Parser)]
struct PreProcOpt {
    #[clap(flatten)]
    pub copt: CommonOpt,
    #[clap(value_parser, short, long = "input")]
    /// Path to unprocessed data in json format.
    pub input_path: PathBuf,
    #[clap(value_parser, short, long = "output")]
    /// Path to write the processed output.
    pub output_path: PathBuf,
}

#[derive(Debug, Parser)]
struct GenerateOpt {
    #[clap(flatten)]
    pub copt: CommonOpt,
    #[clap(value_parser, short, long = "output")]
    /// Path to write the generated output.
    pub output_path: PathBuf,
}

#[derive(Debug, Parser)]
struct SetupOpt {
    #[clap(flatten)]
    pub copt: CommonOpt,
    #[clap(name = "target")]
    pub target: TargetOpt,
    #[clap(value_parser, short, long = "profile")]
    /// Path to the test profile.
    pub profile_path: PathBuf,
}

#[derive(Debug, Parser)]
struct RunOpt {
    #[clap(flatten)]
    pub copt: CommonOpt,
    #[clap(name = "target")]
    pub target: TargetOpt,
    #[clap(
        name = "test-type",
        help = "Which type of test to run against this system: currently supports 'search-basic'"
    )]
    /// Which type of test to run against this system
    pub test_type: TestTypeOpt,
    #[clap(value_parser, short, long = "profile")]
    /// Path to the test profile.
    pub profile_path: PathBuf,
}

#[derive(Debug, Parser)]
/// Configuration options
struct ConfigOpt {
    #[clap(flatten)]
    pub copt: CommonOpt,
    #[clap(value_parser, short, long)]
    /// Update the admin password
    pub admin_password: Option<String>,
    #[clap(value_parser, short, long)]
    /// Update the Kanidm URI
    pub kanidm_uri: Option<String>,
    #[clap(value_parser, short, long)]
    /// Update the LDAP URI
    pub ldap_uri: Option<String>,
    #[clap(value_parser, long)]
    /// Update the LDAP base DN
    pub ldap_base_dn: Option<String>,

    #[clap(value_parser, short = 'D', long)]
    /// Set the configuration name
    pub name: Option<String>,

    #[clap(value_parser, long)]
    /// The data file path to update (or create)
    pub data_file: Option<String>,

    #[clap(value_parser, short, long)]
    /// The place we'll drop the results
    pub results: Option<PathBuf>,

    #[clap(value_parser, short, long)]
    /// The configuration file path to update (or create)
    pub profile: PathBuf,
}

#[derive(Debug, Subcommand, Clone)]
/// The target to run against
pub(crate) enum TargetOpt {
    #[clap(name = "ds")]
    /// Run against the ldap/ds profile
    Ds,
    #[clap(name = "ipa")]
    /// Run against the ipa profile
    Ipa,
    #[clap(name = "kanidm")]
    /// Run against the kanidm http profile
    Kanidm,
    #[clap(name = "kanidm-ldap")]
    /// Run against the kanidm ldap profile
    KanidmLdap,
}

impl FromStr for TargetOpt {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ds" => Ok(TargetOpt::Ds),
            "ipa" => Ok(TargetOpt::Ipa),
            "kanidm" => Ok(TargetOpt::Kanidm),
            "kanidm-ldap" => Ok(TargetOpt::KanidmLdap),
            _ => Err("Invalid target type. Must be ds, ipa, kanidm, or kanidm-ldap"),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
pub(crate) enum TestTypeOpt {
    #[clap(name = "search-basic")]
    /// Perform a basic search-only test
    SearchBasic,
}

impl FromStr for TestTypeOpt {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "search-basic" => Ok(TestTypeOpt::SearchBasic),
            _ => Err("Invalid test type."),
        }
    }
}

impl std::fmt::Display for TestTypeOpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            TestTypeOpt::SearchBasic => write!(f, "search-basic"),
        }
    }
}

#[derive(Debug, Parser)]
#[clap(
    name = "orca",
    about = "Orca Load Testing Utility

Orca works in a few steps.

1. Create an orca config which defines the targets you want to be able to setup and load test. See example_profiles/small/orca.toml

2. (Optional) preprocess an anonymised 389-ds access log (created from an external tool) into an orca data set.

3. 'orca setup' the kanidm/389-ds instance from the orca data set. You can see an example of this in example_profiles/small/data.json. This will reset the database, and add tons of entries etc. For example:

    orca setup kanidm -p ./example_profiles/small/orca.toml

4. 'orca run' one of the metrics, based on that data set. For example:

    orca run -p example_profiles/small/orca.toml kanidm search-basic

"
)]
enum OrcaOpt {
    #[clap(name = "conntest")]
    /// Perform a connection test against the specified target
    TestConnection(SetupOpt),
    #[clap(name = "generate")]
    /// Generate a new dataset that can be used for testing. Parameters can be provided
    /// to affect the type and quantity of data created.
    Generate(GenerateOpt),
    #[clap(name = "preprocess")]
    /// Preprocess a dataset that can be used for testing
    PreProc(PreProcOpt),
    #[clap(name = "setup")]
    /// Setup a server as defined by a test profile
    Setup(SetupOpt),
    #[clap(name = "run")]
    /// Run the load test as defined by the test profile
    Run(RunOpt),
    #[clap(name = "version")]
    /// Print version info and exit
    Version(CommonOpt),
    #[clap(name = "configure")]
    /// Update a config file
    Configure(ConfigOpt),
}
