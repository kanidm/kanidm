
#[derive(Debug, StructOpt)]
struct GroupNamed {
    #[structopt()]
    name: String,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct GroupNamedMembers {
    #[structopt()]
    name: String,
    #[structopt()]
    members: Vec<String>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct GroupPosixOpt {
    #[structopt()]
    name: String,
    #[structopt(long = "gidnumber")]
    gidnumber: Option<u32>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum GroupPosix {
    #[structopt(name = "show")]
    Show(GroupNamed),
    #[structopt(name = "set")]
    Set(GroupPosixOpt),
}

#[derive(Debug, StructOpt)]
enum GroupOpt {
    #[structopt(name = "list")]
    List(CommonOpt),
    #[structopt(name = "create")]
    Create(GroupNamed),
    #[structopt(name = "delete")]
    Delete(GroupNamed),
    #[structopt(name = "list_members")]
    ListMembers(GroupNamed),
    #[structopt(name = "set_members")]
    SetMembers(GroupNamedMembers),
    #[structopt(name = "purge_members")]
    PurgeMembers(GroupNamed),
    #[structopt(name = "add_members")]
    AddMembers(GroupNamedMembers),
    #[structopt(name = "posix")]
    Posix(GroupPosix),
}
