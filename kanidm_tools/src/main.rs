extern crate structopt;
use kanidm_client::KanidmClient;
use std::path::PathBuf;
use structopt::StructOpt;
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
struct SearchOpt {
    #[structopt()]
    filter: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum ClientOpt {
    #[structopt(name = "search")]
    Search(SearchOpt),
    #[structopt(name = "whoami")]
    Whoami(CommonOpt),
}

impl ClientOpt {
    fn debug(&self) -> bool {
        match self {
            ClientOpt::Whoami(copt) => copt.debug,
            ClientOpt::Search(sopt) => sopt.commonopts.debug,
        }
    }
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
        ClientOpt::Whoami(copt) => {
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
        ClientOpt::Search(sopt) => {
            let client = sopt.commonopts.to_client();

            let rset = client.search_str(sopt.filter.as_str()).unwrap();

            for e in rset {
                println!("{:?}", e);
            }
        }
    }
}
