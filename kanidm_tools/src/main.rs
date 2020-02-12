use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::{Entry, Filter, Modify, ModifyList};

use log::debug;
use serde::de::DeserializeOwned;
use shellexpand;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "H", long = "url")]
    addr: Option<String>,
    #[structopt(short = "D", long = "name")]
    username: String,
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
    ca_path: Option<PathBuf>,
}

impl CommonOpt {
    fn to_client(&self) -> KanidmClient {
        let config_path: String = shellexpand::tilde("~/.config/kanidm").into_owned();

        debug!("Attempting to use config {}", "/etc/kanidm/config");
        let client_builder = KanidmClientBuilder::new()
            .read_options_from_optional_config("/etc/kanidm/config")
            .and_then(|cb| {
                debug!("Attempting to use config {}", config_path);
                cb.read_options_from_optional_config(config_path)
            })
            .expect("Failed to parse config (if present)");

        let client_builder = match &self.addr {
            Some(a) => client_builder.address(a.to_string()),
            None => client_builder,
        };

        let ca_path: Option<&str> = self.ca_path.as_ref().map(|p| p.to_str().unwrap());
        let client_builder = match ca_path {
            Some(p) => client_builder
                .add_root_certificate_filepath(p)
                .expect("Failed to access CA file"),
            None => client_builder,
        };

        let client = client_builder
            .build()
            .expect("Failed to build client instance");

        let r = if self.username == "anonymous" {
            client.auth_anonymous()
        } else {
            let password = rpassword::prompt_password_stderr("Enter password: ").unwrap();
            client.auth_simple_password(self.username.as_str(), password.as_str())
        };

        if r.is_err() {
            println!("Error during authentication phase: {:?}", r);
            std::process::exit(1);
        }

        client
    }
}

#[derive(Debug, StructOpt)]
struct FilterOpt {
    #[structopt()]
    filter: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct CreateOpt {
    #[structopt(parse(from_os_str))]
    file: Option<PathBuf>,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct ModifyOpt {
    #[structopt(flatten)]
    commonopts: CommonOpt,
    #[structopt()]
    filter: String,
    #[structopt(parse(from_os_str))]
    file: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
enum RawOpt {
    #[structopt(name = "search")]
    Search(FilterOpt),
    #[structopt(name = "create")]
    Create(CreateOpt),
    #[structopt(name = "modify")]
    Modify(ModifyOpt),
    #[structopt(name = "delete")]
    Delete(FilterOpt),
}

#[derive(Debug, StructOpt)]
struct AccountCommonOpt {
    #[structopt()]
    account_id: String,
}

#[derive(Debug, StructOpt)]
struct AccountCredentialSet {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt()]
    application_id: Option<String>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct AccountNamedOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct AccountNamedTagOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "tag")]
    tag: String,
}

#[derive(Debug, StructOpt)]
struct AccountNamedTagPKOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(flatten)]
    copt: CommonOpt,
    #[structopt(name = "tag")]
    tag: String,
    #[structopt(name = "pubkey")]
    pubkey: String,
}

#[derive(Debug, StructOpt)]
struct AccountCreateOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(name = "display_name")]
    display_name: String,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum AccountCredential {
    #[structopt(name = "set_password")]
    SetPassword(AccountCredentialSet),
    #[structopt(name = "generate_password")]
    GeneratePassword(AccountCredentialSet),
}

#[derive(Debug, StructOpt)]
enum AccountRadius {
    #[structopt(name = "show_secret")]
    Show(AccountNamedOpt),
    #[structopt(name = "generate_secret")]
    Generate(AccountNamedOpt),
    #[structopt(name = "delete_secret")]
    Delete(AccountNamedOpt),
}

#[derive(Debug, StructOpt)]
struct AccountPosixOpt {
    #[structopt(flatten)]
    aopts: AccountCommonOpt,
    #[structopt(long = "gidnumber")]
    gidnumber: Option<u32>,
    #[structopt(long = "shell")]
    shell: Option<String>,
    #[structopt(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum AccountPosix {
    #[structopt(name = "show")]
    Show(AccountNamedOpt),
    #[structopt(name = "set")]
    Set(AccountPosixOpt),
}

#[derive(Debug, StructOpt)]
enum AccountSsh {
    #[structopt(name = "list_publickeys")]
    List(AccountNamedOpt),
    #[structopt(name = "add_publickey")]
    Add(AccountNamedTagPKOpt),
    #[structopt(name = "delete_publickey")]
    Delete(AccountNamedTagOpt),
}

#[derive(Debug, StructOpt)]
enum AccountOpt {
    #[structopt(name = "credential")]
    Credential(AccountCredential),
    #[structopt(name = "radius")]
    Radius(AccountRadius),
    #[structopt(name = "posix")]
    Posix(AccountPosix),
    #[structopt(name = "ssh")]
    Ssh(AccountSsh),
    #[structopt(name = "list")]
    List(CommonOpt),
    #[structopt(name = "get")]
    Get(AccountNamedOpt),
    #[structopt(name = "create")]
    Create(AccountCreateOpt),
    #[structopt(name = "delete")]
    Delete(AccountNamedOpt),
}

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
}

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
            },
        }
    }
}

fn read_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T, Box<dyn Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);

    let t: T = serde_json::from_reader(r)?;
    Ok(t)
}

fn main() {
    let opt = ClientOpt::from_args();

    if opt.debug() {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    match opt {
        ClientOpt::Raw(ropt) => match ropt {
            RawOpt::Search(sopt) => {
                let client = sopt.commonopts.to_client();

                let filter: Filter = serde_json::from_str(sopt.filter.as_str()).unwrap();
                let rset = client.search(filter).unwrap();

                rset.iter().for_each(|e| {
                    println!("{:?}", e);
                });
            }
            RawOpt::Create(copt) => {
                let client = copt.commonopts.to_client();
                // Read the file?
                match copt.file {
                    Some(p) => {
                        let r_entries: Vec<BTreeMap<String, Vec<String>>> = read_file(p).unwrap();
                        let entries = r_entries.into_iter().map(|b| Entry { attrs: b }).collect();
                        client.create(entries).unwrap()
                    }
                    None => {
                        println!("Must provide a file");
                    }
                }
            }
            RawOpt::Modify(mopt) => {
                let client = mopt.commonopts.to_client();
                // Read the file?
                match mopt.file {
                    Some(p) => {
                        let filter: Filter = serde_json::from_str(mopt.filter.as_str()).unwrap();
                        let r_list: Vec<Modify> = read_file(p).unwrap();
                        let modlist = ModifyList::new_list(r_list);
                        client.modify(filter, modlist).unwrap()
                    }
                    None => {
                        println!("Must provide a file");
                    }
                }
            }
            RawOpt::Delete(dopt) => {
                let client = dopt.commonopts.to_client();
                let filter: Filter = serde_json::from_str(dopt.filter.as_str()).unwrap();
                client.delete(filter).unwrap();
            }
        },
        ClientOpt::CSelf(csopt) => match csopt {
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
        },
        ClientOpt::Account(aopt) => match aopt {
            // id/cred/primary/set
            AccountOpt::Credential(acopt) => match acopt {
                AccountCredential::SetPassword(acsopt) => {
                    let client = acsopt.copt.to_client();
                    let password = rpassword::prompt_password_stderr(
                        format!("Enter new password for {}: ", acsopt.aopts.account_id).as_str(),
                    )
                    .unwrap();

                    client
                        .idm_account_primary_credential_set_password(
                            acsopt.aopts.account_id.as_str(),
                            password.as_str(),
                        )
                        .unwrap();
                }
                AccountCredential::GeneratePassword(acsopt) => {
                    let client = acsopt.copt.to_client();

                    let npw = client
                        .idm_account_primary_credential_set_generated(
                            acsopt.aopts.account_id.as_str(),
                        )
                        .unwrap();
                    println!(
                        "Generated password for {}: {}",
                        acsopt.aopts.account_id, npw
                    );
                }
            }, // end AccountOpt::Credential
            AccountOpt::Radius(aropt) => match aropt {
                AccountRadius::Show(aopt) => {
                    let client = aopt.copt.to_client();

                    let rcred = client
                        .idm_account_radius_credential_get(aopt.aopts.account_id.as_str())
                        .unwrap();

                    match rcred {
                        Some(s) => println!("Radius secret: {}", s),
                        None => println!("NO Radius secret"),
                    }
                }
                AccountRadius::Generate(aopt) => {
                    let client = aopt.copt.to_client();
                    client
                        .idm_account_radius_credential_regenerate(aopt.aopts.account_id.as_str())
                        .unwrap();
                }
                AccountRadius::Delete(aopt) => {
                    let client = aopt.copt.to_client();
                    client
                        .idm_account_radius_credential_delete(aopt.aopts.account_id.as_str())
                        .unwrap();
                }
            }, // end AccountOpt::Radius
            AccountOpt::Posix(apopt) => match apopt {
                AccountPosix::Show(aopt) => {
                    let client = aopt.copt.to_client();
                    let token = client
                        .idm_account_unix_token_get(aopt.aopts.account_id.as_str())
                        .unwrap();
                    println!("{:?}", token);
                }
                AccountPosix::Set(aopt) => {
                    let client = aopt.copt.to_client();
                    client
                        .idm_account_unix_extend(
                            aopt.aopts.account_id.as_str(),
                            aopt.gidnumber,
                            aopt.shell.as_deref(),
                        )
                        .unwrap();
                }
            }, // end AccountOpt::Posix
            AccountOpt::Ssh(asopt) => match asopt {
                AccountSsh::List(aopt) => {
                    let client = aopt.copt.to_client();

                    let pkeys = client
                        .idm_account_get_ssh_pubkeys(aopt.aopts.account_id.as_str())
                        .unwrap();

                    for pkey in pkeys {
                        println!("{}", pkey)
                    }
                }
                AccountSsh::Add(aopt) => {
                    let client = aopt.copt.to_client();
                    client
                        .idm_account_post_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                            aopt.pubkey.as_str(),
                        )
                        .unwrap();
                }
                AccountSsh::Delete(aopt) => {
                    let client = aopt.copt.to_client();
                    client
                        .idm_account_delete_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                        )
                        .unwrap();
                }
            }, // end AccountOpt::Ssh
            AccountOpt::List(copt) => {
                let client = copt.to_client();
                let r = client.idm_account_list().unwrap();
                for e in r {
                    println!("{:?}", e);
                }
            }
            AccountOpt::Get(aopt) => {
                let client = aopt.copt.to_client();
                let e = client
                    .idm_account_get(aopt.aopts.account_id.as_str())
                    .unwrap();
                println!("{:?}", e);
            }
            AccountOpt::Delete(aopt) => {
                let client = aopt.copt.to_client();
                client
                    .idm_account_delete(aopt.aopts.account_id.as_str())
                    .unwrap();
            }
            AccountOpt::Create(acopt) => {
                let client = acopt.copt.to_client();
                client
                    .idm_account_create(
                        acopt.aopts.account_id.as_str(),
                        acopt.display_name.as_str(),
                    )
                    .unwrap();
            }
        }, // end Account
        ClientOpt::Group(gopt) => match gopt {
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
        }, // end Group
    }
}
