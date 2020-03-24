use kanidm_proto::v1::{Entry, Filter, Modify, ModifyList};
use kanidm_client::{KanidmClient, KanidmClientBuilder};

pub mod account;
pub mod common;
pub mod group;
pub mod raw;
pub mod recycle;


use crate::ClientOpt;
use crate::account::AccountOpt;
use crate::group::GroupOpt;
use crate::raw::{RawOpt, SelfOpt};
use crate::recycle::RecycleOpt;


#[derive(Debug, StructOpt)]
enum SelfOpt {
    #[structopt(name = "whoami")]
    Whoami(CommonOpt),
    #[structopt(name = "set_password")]
    SetPassword(CommonOpt),
}

impl SelfOpt {
    pub fn exec(&self) -> () {
        match self {
            SelfOpt::Whoami(copt) => {
                let client = copt.to_client();

                match client.whoami() {
                    Ok(o_ent) => match o_ent {
                        Some((ent, uat)) => {
                            debug!("{:?}", ent);
                            println!("{}", uat);
                        }
                        None => println!("Unauthenticated"),
                    },
                    Err(e) => println!("Error: {:?}", e),
                }
            }

            SelfOpt::SetPassword(copt) => {
                let client = copt.to_client();

                let password = rpassword::prompt_password_stderr("Enter new password: ").unwrap();

                client.idm_account_set_password(password).unwrap();
            }

        }
    }
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

impl ClientOpt {
    fn debug(&self) -> bool {
        match self {
            ClientOpt::Raw(ropt) => match ropt {
                RawOpt::Search(sopt) => sopt.commonopts.debug,
                RawOpt::Create(copt) => copt.commonopts.debug,
                RawOpt::Modify(mopt) => mopt.commonopts.debug,
                RawOpt::Delete(dopt) => dopt.commonopts.debug,
            },
            ClientOpt::CSelf(csopt) => match csopt {
                SelfOpt::Whoami(copt) => copt.debug,
                SelfOpt::SetPassword(copt) => copt.debug,
            },
            ClientOpt::Account(aopt) => match aopt {
                AccountOpt::Credential(acopt) => match acopt {
                    AccountCredential::SetPassword(acs) => acs.copt.debug,
                    AccountCredential::GeneratePassword(acs) => acs.copt.debug,
                },
                AccountOpt::Radius(acopt) => match acopt {
                    AccountRadius::Show(aro) => aro.copt.debug,
                    AccountRadius::Generate(aro) => aro.copt.debug,
                    AccountRadius::Delete(aro) => aro.copt.debug,
                },
                AccountOpt::Posix(apopt) => match apopt {
                    AccountPosix::Show(apo) => apo.copt.debug,
                    AccountPosix::Set(apo) => apo.copt.debug,
                    AccountPosix::SetPassword(apo) => apo.copt.debug,
                },
                AccountOpt::Ssh(asopt) => match asopt {
                    AccountSsh::List(ano) => ano.copt.debug,
                    AccountSsh::Add(ano) => ano.copt.debug,
                    AccountSsh::Delete(ano) => ano.copt.debug,
                },
                AccountOpt::List(copt) => copt.debug,
                AccountOpt::Get(aopt) => aopt.copt.debug,
                AccountOpt::Delete(aopt) => aopt.copt.debug,
                AccountOpt::Create(aopt) => aopt.copt.debug,
            },
            ClientOpt::Group(gopt) => match gopt {
                GroupOpt::List(copt) => copt.debug,
                GroupOpt::Create(gcopt) => gcopt.copt.debug,
                GroupOpt::Delete(gcopt) => gcopt.copt.debug,
                GroupOpt::ListMembers(gcopt) => gcopt.copt.debug,
                GroupOpt::AddMembers(gcopt) => gcopt.copt.debug,
                GroupOpt::SetMembers(gcopt) => gcopt.copt.debug,
                GroupOpt::PurgeMembers(gcopt) => gcopt.copt.debug,
                GroupOpt::Posix(gpopt) => match gpopt {
                    GroupPosix::Show(gcopt) => gcopt.copt.debug,
                    GroupPosix::Set(gcopt) => gcopt.copt.debug,
                },
            },
        }
    }

    pub fn exec(&self) -> () {
        match self {
            ClientOpt::Raw(ropt) => ropt.exec(),
            ClientOpt::CSelf(csopt) => csopt.exec(),
            ClientOpt::Account(aopt) => aopt.exec(),
            ClientOpt::Group(gopt) => gopt.exec(),
            ClientOpt::Recycle(ropt) => ropt.exec(),
        }
    }
}

