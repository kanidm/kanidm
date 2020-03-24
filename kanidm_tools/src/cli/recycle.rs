use crate::common::{CommonOpt, Named};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub enum RecycleOpt {
    #[structopt(name = "list")]
    List(CommonOpt),
    #[structopt(name = "get")]
    Get(Named),
    #[structopt(name = "revive")]
    Revive(Named),
}

impl RecycleOpt {
    pub fn debug(&self) -> bool {
        match self {
            RecycleOpt::List(copt) => copt.debug,
            RecycleOpt::Get(nopt) => nopt.copt.debug,
            RecycleOpt::Revive(nopt) => nopt.copt.debug,
        }
    }

    pub fn exec(&self) -> () {
        match self {
            RecycleOpt::List(copt) => {}
            RecycleOpt::Get(nopt) => {}
            RecycleOpt::Revive(nopt) => {}
        }
    }
}
