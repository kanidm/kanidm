use crate::session::read_tokens;
use crate::CommonOpt;
use compact_jwt::{Jws, JwsUnverified};
use dialoguer::{theme::ColorfulTheme, Select};
use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::v1::UserAuthToken;
use std::str::FromStr;

impl CommonOpt {
    pub fn to_unauth_client(&self) -> KanidmClient {
        let config_path: String = shellexpand::tilde("~/.config/kanidm").into_owned();

        let client_builder = KanidmClientBuilder::new()
            .read_options_from_optional_config("/etc/kanidm/config")
            .and_then(|cb| cb.read_options_from_optional_config(&config_path))
            .unwrap_or_else(|e| {
                error!("Failed to parse config (if present) -- {:?}", e);
                std::process::exit(1);
            });
        debug!(
            "Successfully loaded configuration, looked in /etc/kanidm/config and {} - client builder state: {:?}",
            &config_path, &client_builder
        );

        let client_builder = match &self.addr {
            Some(a) => client_builder.address(a.to_string()),
            None => client_builder,
        };

        let ca_path: Option<&str> = self.ca_path.as_ref().and_then(|p| p.to_str());
        let client_builder = match ca_path {
            Some(p) => {
                debug!("Adding trusted CA cert {:?}", p);
                client_builder
                    .add_root_certificate_filepath(p)
                    .unwrap_or_else(|e| {
                        error!("Failed to add ca certificate -- {:?}", e);
                        std::process::exit(1);
                    })
            }
            None => client_builder,
        };

        debug!(
            "Post attempting to add trusted CA cert, client builder state: {:?}",
            client_builder
        );

        client_builder.build().unwrap_or_else(|e| {
            error!("Failed to build client instance -- {:?}", e);
            std::process::exit(1);
        })
    }

    pub async fn to_client(&self) -> KanidmClient {
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
                    debug!("Using cached token for name {}", f_uname);
                    f_token.clone()
                } else {
                    // Unable to automatically select the user because multiple tokens exist
                    // so we'll prompt the user to select one
                    match prompt_for_username_get_token() {
                        Ok(value) => value,
                        Err(msg) => {
                            error!("{}", msg);
                            std::process::exit(1);
                        }
                    }
                }
            }
        };

        let jwtu = match JwsUnverified::from_str(&token) {
            Ok(jwtu) => jwtu,
            Err(e) => {
                error!("Unable to parse token - {:?}", e);
                std::process::exit(1);
            }
        };

        // Is the token (probably) valid?
        match jwtu
            .validate_embeded()
            .map(|jws: Jws<UserAuthToken>| jws.inner)
        {
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
        client.set_token(token).await;

        client
    }
}

/// This parses the token store and prompts the user to select their username, returns the username/token as a tuple of Strings
///
/// Used to reduce duplication in implementing [prompt_for_username_get_username] and [prompt_for_username_get_token]
pub fn prompt_for_username_get_values() -> Result<(String, String), String> {
    let tokens = match read_tokens() {
        Ok(value) => value,
        _ => return Err("Error retrieving authentication token store".to_string()),
    };
    if tokens.is_empty() {
        error!("No tokens in store, quitting!");
        std::process::exit(1);
    }
    let mut options = Vec::new();
    for option in tokens.iter() {
        options.push(String::from(option.0));
    }
    let user_select = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Multiple authentication tokens exist. Please select one")
        .default(0)
        .items(&options)
        .interact();
    let selection = match user_select {
        Err(error) => {
            error!("Failed to handle user input: {:?}", error);
            std::process::exit(1);
        }
        Ok(value) => value,
    };
    debug!("Index of the chosen menu item: {:?}", selection);

    match tokens.iter().nth(selection) {
        Some(value) => {
            let (f_uname, f_token) = value;
            debug!("Using cached token for name {}", f_uname);
            debug!("Cached token: {}", f_token);
            Ok((f_uname.to_string(), f_token.to_string()))
        }
        None => {
            error!("Memory corruption trying to read token store, quitting!");
            std::process::exit(1);
        }
    }
}

/// This parses the token store and prompts the user to select their username, returns the username as a String
///
/// Powered by [prompt_for_username_get_values]
pub fn prompt_for_username_get_username() -> Result<String, String> {
    match prompt_for_username_get_values() {
        Ok(value) => {
            let (f_user, _) = value;
            Ok(f_user)
        }
        Err(err) => Err(err),
    }
}

/// This parses the token store and prompts the user to select their username, returns the token as a String
///
/// Powered by [prompt_for_username_get_values]
pub fn prompt_for_username_get_token() -> Result<String, String> {
    match prompt_for_username_get_values() {
        Ok(value) => {
            let (_, f_token) = value;
            Ok(f_token)
        }
        Err(err) => Err(err),
    }
}
