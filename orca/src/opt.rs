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
#[structopt(about = "Orca Load Testing Utility")]
enum OrcaOpt {
    #[structopt(name = "preprocess")]
    /// Preprocess a dataset that can be used for testing
    PreProc(PreProcOpt),
    #[structopt(name = "setup")]
    /// Setup a server as defined by a test profile
    Setup(SetupOpt),
    #[structopt(name = "run")]
    /// Run the load test as define by the test profile
    Run(RunOpt),
}


