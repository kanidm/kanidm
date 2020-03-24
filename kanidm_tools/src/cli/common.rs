use kanidm_client::{KanidmClient, KanidmClientBuilder};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Named {
    #[structopt()]
    pub name: String,
    #[structopt(flatten)]
    pub copt: CommonOpt,
}

#[derive(Debug, StructOpt)]
pub struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    pub debug: bool,
    #[structopt(short = "H", long = "url")]
    pub addr: Option<String>,
    #[structopt(short = "D", long = "name")]
    pub username: String,
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
    pub ca_path: Option<PathBuf>,
}

impl CommonOpt {
    pub fn to_client(&self) -> KanidmClient {
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
