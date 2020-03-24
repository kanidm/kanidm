pub mod account;
pub mod common;
pub mod group;
pub mod raw;
pub mod recycle;


#[derive(Debug, StructOpt)]
enum SelfOpt {
    #[structopt(name = "whoami")]
    Whoami(CommonOpt),
    #[structopt(name = "set_password")]
    SetPassword(CommonOpt),
}

#[derive(Debug, StructOpt)]
enum ClientOpt {
    #[structopt(name = "raw")]
    Raw(RawOpt),
    #[structopt(name = "self")]
    CSelf(SelfOpt),
    #[structopt(name = "account")]
    Account(AccountOpt),
    #[structopt(name = "group")]
    Group(GroupOpt),
    #[structopt(name = "recycle_bin")]
    Recycle(RecycleOpt),

}
