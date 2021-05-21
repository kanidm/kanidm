use crate::session::read_tokens;
use crate::CommonOpt;
use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UserAuthToken;

impl CommonOpt {
    pub fn to_unauth_client(&self) -> KanidmClient {
        let config_path: String = shellexpand::tilde("~/.config/kanidm").into_owned();

        let client_builder = match KanidmClientBuilder::new()
            .read_options_from_optional_config("/etc/kanidm/config")
            .and_then(|cb| cb.read_options_from_optional_config(&config_path))
        {
            Ok(c) => {
                debug!("Successfully read configuration from {}", &config_path);
                c
            }
            Err(e) => {
                error!("Failed to parse config (if present) -- {:?}", e);
                std::process::exit(1);
            }
        };

        let client_builder = match &self.addr {
            Some(a) => client_builder.address(a.to_string()),
            None => client_builder,
        };

        let ca_path: Option<&str> = self.ca_path.as_ref().map(|p| p.to_str()).flatten();
        let client_builder = match ca_path {
            Some(p) => match client_builder.add_root_certificate_filepath(p) {
                Ok(cb) => cb,
                Err(e) => {
                    error!("Failed to add ca certificate -- {:?}", e);
                    std::process::exit(1);
                }
            },
            None => client_builder,
        };

        match client_builder.build() {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to build client instance -- {:?}", e);
                std::process::exit(1);
            }
        }
    }

    pub fn to_client(&self) -> KanidmClient {
        let client = self.to_unauth_client();
        // Read the token file.
        let tokens = match read_tokens() {
            Ok(t) => t,
            Err(_e) => {
                error!("Error retrieving authentication token store");
                std::process::exit(1);
            }
        };

        if tokens.is_empty() {
            error!(
                "No valid authentication tokens found. Please login with the 'login' subcommand."
            );
            std::process::exit(1);
        }

        // If we have a username, use that to select tokens
        let token = match &self.username {
            Some(username) => {
                // Is it in the store?
                match tokens.get(username) {
                    Some(t) => t.clone(),
                    None => {
                        error!("No valid authentication tokens found for {}.", username);
                        std::process::exit(1);
                    }
                }
            }
            None => {
                if tokens.len() == 1 {
                    #[allow(clippy::expect_used)]
                    let (f_uname, f_token) = tokens.iter().next().expect("Memory Corruption");
                    // else pick the first token
                    info!("Using cached token for name {}", f_uname);
                    f_token.clone()
                } else {
                    // Unable to select
                    error!("Multiple authentication tokens exist. Please select one with --name.");
                    std::process::exit(1);
                }
            }
        };

        // Is the token (probably) valid?
        match unsafe { bundy::Data::parse_without_verification::<UserAuthToken>(&token) } {
            Ok(uat) => {
                if time::OffsetDateTime::now_utc() >= uat.expiry {
                    error!(
                        "Session has expired for {} - you may need to login again.",
                        uat.spn
                    );
                    std::process::exit(1);
                }
            }
            Err(_e) => {
                error!("Unable to read token for requested user - you may need to login again.");
                std::process::exit(1);
            }
        };

        // Set it into the client
        client.set_token(token);

        client
    }
}
