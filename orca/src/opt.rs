use std::str::FromStr;

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    /// Enable debug logging
    pub debug: bool,
}


#[derive(Debug, StructOpt)]
struct PreProcOpt {
    #[structopt(flatten)]
    pub copt: CommonOpt,
    #[structopt(parse(from_os_str), short = "i", long = "input")]
    /// Path to unprocessed data in json format.
    pub input_path: PathBuf,
    #[structopt(parse(from_os_str), short = "o", long = "output")]
    /// Path to write the processed output.
    pub output_path: PathBuf,
}


#[derive(Debug, StructOpt)]
struct SetupOpt {
    #[structopt(flatten)]
    pub copt: CommonOpt,
    #[structopt(name = "target")]
    /// Which service to target during this operation.
    /// Valid values are "ds" or "kanidm"
    pub target: TargetOpt,
    #[structopt(parse(from_os_str), short = "p", long = "profile")]
    /// Path to the test profile.
    pub profile_path: PathBuf,
}

#[derive(Debug, StructOpt)]
struct RunOpt {
    #[structopt(flatten)]
    pub copt: CommonOpt,
    #[structopt(name = "target")]
    /// Which service to target during this operation.
    /// Valid values are "ds" or "kanidm"
    pub target: TargetOpt,
    #[structopt(name = "test_type")]
    /// Which type of test to run against this system
    pub test_type: TestTypeOpt,
    #[structopt(parse(from_os_str), short = "p", long = "profile")]
    /// Path to the test profile.
    pub profile_path: PathBuf,
}

#[derive(Debug, StructOpt)]
pub(crate) enum TargetOpt {
    #[structopt(name = "ds")]
    /// Run against the ldap/ds profile
    Ds,
    #[structopt(name = "kanidm")]
    /// Run against the kanidm http profile
    Kanidm,
    #[structopt(name = "kanidm_ldap")]
    /// Run against the kanidm ldap profile
    KanidmLdap,
}

impl FromStr for TargetOpt {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ds" => Ok(TargetOpt::Ds),
            "kanidm" => Ok(TargetOpt::Kanidm),
            "kanidm_ldap" => Ok(TargetOpt::KanidmLdap),
            _ => Err("Invalid target type. Must be ds, kanidm, or kanidm_ldap"),
        }
    }
}

#[derive(Debug, StructOpt)]
pub(crate) enum TestTypeOpt {
    #[structopt(name = "search-basic")]
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

#[derive(Debug, StructOpt)]
#[structopt(name="orca", about = "Orca Load Testing Utility

Orca works in a few steps.

1. (Optional) preprocess an anonymised 389-ds access log (created from an external tool) into an orca data set.
Create an orca config which defines the targets you want to be able to setup and load test. See example_profiles/small/orca.toml
2. 'orca setup' the kanidm/389-ds instance from the orca data set. You can see an example of this in example_profiles/small/data.json. This will reset the database, and add tons of entries etc.
3. 'orca run' one of the metrics, based on that data set. For example:

    orca run -p example_profiles/small/orca.toml kanidm search-basic

")]
enum OrcaOpt {
    #[structopt(name = "preprocess")]
    /// Preprocess a dataset that can be used for testing
    PreProc(PreProcOpt),
    #[structopt(name = "setup")]
    /// Setup a server as defined by a test profile
    Setup(SetupOpt),
    #[structopt(name = "run")]
    /// Run the load test as defined by the test profile
    Run(RunOpt),
}


