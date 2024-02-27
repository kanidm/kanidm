
#[derive(Debug, Parser)]
struct CommonOpt {
    #[clap(short, long)]
    /// Enable debug logging
    pub debug: bool,
}

#[derive(Debug, Parser)]
#[clap(
    name = "orca",
    about = "Orca Load Testing Utility"
)]
enum OrcaOpt {
    /*
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
    #[clap(name = "configure")]
    /// Update a config file
    Configure(ConfigOpt),
    */

    SetupWizard {
        #[clap(flatten)]
        common: CommonOpt,

        #[clap(long)]
        /// Update the admin password
        admin_password: String,

        #[clap(long)]
        /// Update the idm_admin password
        idm_admin_password: String,

        #[clap(long)]
        /// Update the Kanidm URI
        control_uri: String,

        #[clap(long)]
        /// Optional RNG seed. Takes an unsigned 64bit integer. This allows
        /// deterministic regeneration of a test state file.
        seed: Option<u64>,

        // Todo - support the extra uris field for replicated tests.

        #[clap(long = "profile")]
        /// The configuration file path to update (or create)
        profile_path: PathBuf,
    },

    #[clap(name = "conntest")]
    /// Perform a connection test
    TestConnection {
        #[clap(flatten)]
        common: CommonOpt,
        #[clap(long = "profile")]
        /// Path to the test profile.
        profile_path: PathBuf,
    },

    #[clap(name = "populate")]
    /// Create a new state file that is populated with a complete dataset, ready
    /// to be loaded into a kanidm instance.
    PopulateData {
        #[clap(flatten)]
        common: CommonOpt,
        #[clap(long = "profile")]
        /// Path to the test profile.
        profile_path: PathBuf,
        #[clap(long = "state")]
        /// Path to the state file.
        state_path: PathBuf,
    },

    #[clap(name = "preflight")]
    /// Populate the data for the test into the Kanidm instance.
    Preflight {
        #[clap(flatten)]
        common: CommonOpt,
        #[clap(long = "state")]
        /// Path to the state file.
        state_path: PathBuf,
    },

    #[clap(name = "run")]
    /// Run the simulation.
    Run {
        #[clap(flatten)]
        common: CommonOpt,
        #[clap(long = "state")]
        /// Path to the state file.
        state_path: PathBuf,
    },

    #[clap(name = "version")]
    /// Print version info and exit
    Version {
        #[clap(flatten)]
        common: CommonOpt
    },
}
