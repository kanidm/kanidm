use std::env;
use std::str::FromStr;

use async_recursion::async_recursion;
use compact_jwt::{Jws, JwsUnverified};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Select};
use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::constants::{DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH_HOME};
use kanidm_proto::v1::UserAuthToken;

use crate::session::read_tokens;
use crate::{CommonOpt, LoginOpt, ReauthOpt};

#[derive(Clone)]
pub enum OpType {
    Read,
    Write,
}

#[derive(Debug)]
pub enum ToClientError {
    NeedLogin(String),
    NeedReauth(String),
    Other,
}

impl CommonOpt {
    pub fn to_unauth_client(&self) -> KanidmClient {
        let config_path: String = shellexpand::tilde(DEFAULT_CLIENT_CONFIG_PATH_HOME).into_owned();

        let client_builder = KanidmClientBuilder::new()
            .read_options_from_optional_config(DEFAULT_CLIENT_CONFIG_PATH)
            .map_err(|e| {
                error!(
                    "Failed to parse config ({:?}) -- {:?}",
                    DEFAULT_CLIENT_CONFIG_PATH, e
                );
                e
            })
            .and_then(|cb| {
                cb.read_options_from_optional_config(&config_path)
                    .map_err(|e| {
                        error!("Failed to parse config ({:?}) -- {:?}", config_path, e);
                        e
                    })
            })
            .unwrap_or_else(|_e| {
                std::process::exit(1);
            });
        debug!(
            "Successfully loaded configuration, looked in {} and {} - client builder state: {:?}",
            DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH_HOME, &client_builder
        );

        let client_builder = match &self.addr {
            Some(a) => client_builder.address(a.to_string()),
            None => client_builder,
        };

        let ca_path: Option<&str> = self.ca_path.as_ref().and_then(|p| p.to_str());
        let client_builder = match ca_path {
            Some(p) => {
                debug!("Adding trusted CA cert {:?}", p);
                let client_builder = client_builder
                    .add_root_certificate_filepath(p)
                    .unwrap_or_else(|e| {
                        error!("Failed to add ca certificate -- {:?}", e);
                        std::process::exit(1);
                    });

                debug!(
                    "After attempting to add trusted CA cert, client builder state: {:?}",
                    client_builder
                );
                client_builder
            }
            None => client_builder,
        };

        let client_builder = match self.skip_hostname_verification {
            true => {
                warn!(
                    "Accepting invalid hostnames on the certificate for {:?}",
                    &self.addr
                );
                client_builder.danger_accept_invalid_hostnames(true)
            }
            false => client_builder,
        };

        client_builder.build().unwrap_or_else(|e| {
            error!("Failed to build client instance -- {:?}", e);
            std::process::exit(1);
        })
    }

    async fn try_to_client(&self, optype: OpType) -> Result<KanidmClient, ToClientError> {
        let client = self.to_unauth_client();
        // Read the token file.
        let tokens = match read_tokens() {
            Ok(t) => t,
            Err(_e) => {
                error!("Error retrieving authentication token store");
                return Err(ToClientError::Other);
            }
        };

        if tokens.is_empty() {
            error!(
                "No valid authentication tokens found. Please login with the 'login' subcommand."
            );
            return Err(ToClientError::Other);
        }

        // If we have a username, use that to select tokens
        let (spn, token) = match &self.username {
            Some(filter_username) => {
                let possible_token = if filter_username.contains('@') {
                    // If there is an @, it's an spn so just get the token directly.
                    tokens
                        .get(filter_username)
                        .map(|t| (filter_username.clone(), t.clone()))
                } else {
                    // first we try to find user@hostname
                    let filter_username_with_hostname = format!(
                        "{}@{}",
                        filter_username,
                        client.get_origin().host_str().unwrap_or("localhost")
                    );
                    debug!(
                        "Looking for tokens matching {}",
                        filter_username_with_hostname
                    );

                    let mut token_refs: Vec<_> = tokens
                        .iter()
                        .filter(|(t, _)| *t == &filter_username_with_hostname)
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();

                    if token_refs.len() == 1 {
                        // return the token
                        token_refs.pop()
                    } else {
                        // otherwise let's try the fallback
                        let filter_username = format!("{}@", filter_username);
                        // Filter for tokens that match the pattern
                        let mut token_refs: Vec<_> = tokens
                            .into_iter()
                            .filter(|(t, _)| t.starts_with(&filter_username))
                            .map(|(k, v)| (k, v))
                            .collect();

                        match token_refs.len() {
                            0 => None,
                            1 => token_refs.pop(),
                            _ => {
                                error!("Multiple authentication tokens found for {}. Please specify the full spn to proceed", filter_username);
                                return Err(ToClientError::Other);
                            }
                        }
                    }
                };

                // Is it in the store?
                match possible_token {
                    Some(t) => t,
                    None => {
                        error!(
                            "No valid authentication tokens found for {}.",
                            filter_username
                        );
                        return Err(ToClientError::NeedLogin(filter_username.clone()));
                    }
                }
            }
            None => {
                if tokens.len() == 1 {
                    #[allow(clippy::expect_used)]
                    let (f_uname, f_token) = tokens.iter().next().expect("Memory Corruption");
                    // else pick the first token
                    debug!("Using cached token for name {}", f_uname);
                    (f_uname.clone(), f_token.clone())
                } else {
                    // Unable to automatically select the user because multiple tokens exist
                    // so we'll prompt the user to select one
                    match prompt_for_username_get_values() {
                        Ok(tuple) => tuple,
                        Err(msg) => {
                            error!("Error: {}", msg);
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
                return Err(ToClientError::Other);
            }
        };

        // Is the token (probably) valid?
        match jwtu
            .validate_embeded()
            .map(|jws: Jws<UserAuthToken>| jws.into_inner())
        {
            Ok(uat) => {
                let now_utc = time::OffsetDateTime::now_utc();
                if let Some(exp) = uat.expiry {
                    if now_utc >= exp {
                        error!(
                            "Session has expired for {} - you may need to login again.",
                            uat.spn
                        );
                        return Err(ToClientError::NeedLogin(spn));
                    }
                }

                // Check what we are doing based on op.
                match optype {
                    OpType::Read => {}
                    OpType::Write => {
                        if !uat.purpose_readwrite_active(now_utc + time::Duration::new(20, 0)) {
                            error!(
                                "Privileges have expired for {} - you need to re-authenticate again.",
                                uat.spn
                            );
                            return Err(ToClientError::NeedReauth(spn));
                        }
                    }
                }
            }
            Err(e) => {
                error!("Unable to read token for requested user - you may need to login again.");
                debug!(?e, "JWT Error");
                return Err(ToClientError::NeedLogin(spn));
            }
        };

        // Set it into the client
        client.set_token(token).await;

        Ok(client)
    }

    #[async_recursion]
    pub async fn to_client(&self, optype: OpType) -> KanidmClient {
        match self.try_to_client(optype.clone()).await {
            Ok(c) => c,
            Err(e) => {
                match e {
                    ToClientError::NeedLogin(username) => {
                        if !Confirm::new()
                            .with_prompt("Would you like to login again?")
                            .default(true)
                            .interact()
                            .expect("Failed to interact with interactive session")
                        {
                            std::process::exit(1);
                        }
                        let mut copt = self.clone();
                        copt.username = Some(username);
                        let login_opt = LoginOpt {
                            copt,
                            password: env::var("KANIDM_PASSWORD").ok(),
                        };
                        login_opt.exec().await;
                        // we still use `to_client` instead of `try_to_client` because we may need to prompt user to re-auth again.
                        // since reauth_opt will call `to_client`, this function is recursive anyway.
                        // we use copt since it's username is updated.
                        return login_opt.copt.to_client(optype).await;
                    }
                    ToClientError::NeedReauth(username) => {
                        if !Confirm::new()
                            .with_prompt("Would you like to re-authenticate?")
                            .default(true)
                            .interact()
                            .expect("Failed to interact with interactive session")
                        {
                            std::process::exit(1);
                        }
                        let mut copt = self.clone();
                        copt.username = Some(username);
                        let reauth_opt = ReauthOpt { copt };
                        // calls `to_client` recursively
                        // but should not goes into `NeedLogin` branch again
                        reauth_opt.exec().await;
                        if let Ok(c) = reauth_opt.copt.try_to_client(optype).await {
                            return c;
                        }
                    }
                    ToClientError::Other => {
                        std::process::exit(1);
                    }
                }
                std::process::exit(1);
            }
        }
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
