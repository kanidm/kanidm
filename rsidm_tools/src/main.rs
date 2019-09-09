extern crate structopt;
use rsidm_client::RsidmClient;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "H", long = "url")]
    addr: String,
    #[structopt(short = "D", long = "name")]
    username: String,
}

impl CommonOpt {
    fn to_client(&self) -> RsidmClient {
        RsidmClient::new(self.addr.as_str())
    }
}

#[derive(Debug, StructOpt)]
enum ClientOpt {
    #[structopt(name = "whoami")]
    Whoami(CommonOpt),
}

fn main() {
    let opt = ClientOpt::from_args();

    match opt {
        ClientOpt::Whoami(copt) => {
            let client = copt.to_client();
            let r = if copt.username == "anonymous" {
                client.auth_anonymous()
            } else {
                let password = rpassword::prompt_password_stderr("Enter password: ").unwrap();
                client.auth_simple_password(copt.username.as_str(), password.as_str())
            };

            if r.is_err() {
                println!("Error during authentication phase: {:?}", r);
                return;
            }

            match client.whoami() {
                Ok(o_ent) => match o_ent {
                    Some((_ent, uat)) => {
                        println!("{}", uat);
                    }
                    None => println!("Unauthenticated"),
                },
                Err(e) => println!("Error: {:?}", e),
            }
        }
    }
}
