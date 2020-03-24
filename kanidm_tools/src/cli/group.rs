
#[derive(Debug, StructOpt)]
pub struct GroupNamed {
    #[structopt()]
    name: String,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct GroupNamedMembers {
    #[structopt()]
    name: String,
    #[structopt()]
    members: Vec<String>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct GroupPosixOpt {
    #[structopt()]
    name: String,
    #[structopt(long = "gidnumber")]
    gidnumber: Option<u32>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub enum GroupPosix {
    #[structopt(name = "show")]
    Show(GroupNamed),
    #[structopt(name = "set")]
    Set(GroupPosixOpt),
}

#[derive(Debug, StructOpt)]
pub enum GroupOpt {
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

impl GroupOpt {
    pub fn exec(&self) -> () {
        match self {
            GroupOpt::List(copt) => {
                let client = copt.to_client();
                let r = client.idm_group_list().unwrap();
                for e in r {
                    println!("{:?}", e);
                }
            }
            GroupOpt::Create(gcopt) => {
                let client = gcopt.copt.to_client();
                client.idm_group_create(gcopt.name.as_str()).unwrap();
            }
            GroupOpt::Delete(gcopt) => {
                let client = gcopt.copt.to_client();
                client.idm_group_delete(gcopt.name.as_str()).unwrap();
            }
            GroupOpt::PurgeMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                client.idm_group_purge_members(gcopt.name.as_str()).unwrap();
            }
            GroupOpt::ListMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let members = client.idm_group_get_members(gcopt.name.as_str()).unwrap();
                if let Some(groups) = members {
                    for m in groups {
                        println!("{:?}", m);
                    }
                }
            }
            GroupOpt::AddMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let new_members: Vec<&str> = gcopt.members.iter().map(|s| s.as_str()).collect();

                client
                    .idm_group_add_members(gcopt.name.as_str(), new_members)
                    .unwrap();
            }
            GroupOpt::SetMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let new_members: Vec<&str> = gcopt.members.iter().map(|s| s.as_str()).collect();

                client
                    .idm_group_set_members(gcopt.name.as_str(), new_members)
                    .unwrap();
            }
            GroupOpt::Posix(gpopt) => match gpopt {
                GroupPosix::Show(gcopt) => {
                    let client = gcopt.copt.to_client();
                    let token = client
                        .idm_group_unix_token_get(gcopt.name.as_str())
                        .unwrap();
                    println!("{:?}", token);
                }
                GroupPosix::Set(gcopt) => {
                    let client = gcopt.copt.to_client();
                    client
                        .idm_group_unix_extend(gcopt.name.as_str(), gcopt.gidnumber)
                        .unwrap();
                }
            },
        } // end match
    }
}
