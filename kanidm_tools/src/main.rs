extern crate structopt;
use kanidm_client::KanidmClient;
use kanidm_proto::v1::{Entry, Filter, Modify, ModifyList};
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use structopt::StructOpt;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

extern crate env_logger;
#[macro_use]
extern crate log;

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(short = "H", long = "url")]
    addr: String,
    #[structopt(short = "D", long = "name")]
    username: String,
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
    ca_path: Option<PathBuf>,
}

impl CommonOpt {
    fn to_client(&self) -> KanidmClient {
        let ca_path: Option<&str> = self.ca_path.as_ref().map(|p| p.to_str().unwrap());
        let client = KanidmClient::new(self.addr.as_str(), ca_path);

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
enum AccountCredential {
    #[structopt(name = "set_password")]
    SetPassword(AccountCredentialSet),
    #[structopt(name = "generate_password")]
    GeneratePassword(AccountCredentialSet),
}

#[derive(Debug, StructOpt)]
enum AccountOpt {
    #[structopt(name = "credential")]
    Credential(AccountCredential),
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
                _ => false,
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
        },
    }
}
