use crate::common::prompt_for_username_get_username;
use crate::{LoginOpt, LogoutOpt, SessionOpt};

use kanidm_client::{ClientError, KanidmClient};
use kanidm_proto::v1::{AuthAllowed, AuthResponse, AuthState, UserAuthToken};
#[cfg(target_family = "unix")]
use libc::umask;
use std::collections::BTreeMap;
use std::fs::{create_dir, File};
use std::io::ErrorKind;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::str::FromStr;
use webauthn_authenticator_rs::{u2fhid::U2FHid, RequestChallengeResponse, WebauthnAuthenticator};

use dialoguer::{theme::ColorfulTheme, Select};

use compact_jwt::JwsUnverified;

static TOKEN_DIR: &str = "~/.cache";
static TOKEN_PATH: &str = "~/.cache/kanidm_tokens";

#[allow(clippy::result_unit_err)]
pub fn read_tokens() -> Result<BTreeMap<String, String>, ()> {
    let token_path = PathBuf::from(shellexpand::tilde(TOKEN_PATH).into_owned());
    if !token_path.exists() {
        debug!(
            "Token cache file path {:?} does not exist, returning an empty token store.",
            TOKEN_PATH
        );
        return Ok(BTreeMap::new());
    }

    debug!("Attempting to read tokens from {:?}", &token_path);
    // If the file does not exist, return Ok<map>
    let file = match File::open(&token_path) {
        Ok(f) => f,
        Err(e) => {
            match e.kind() {
                ErrorKind::PermissionDenied => {
                    // we bail here because you won't be able to write them back...
                    error!(
                        "Permission denied reading token store file {:?}",
                        &token_path
                    );
                    return Err(());
                }
                // other errors are OK to continue past
                _ => {
                    warn!(
                        "Cannot read tokens from {} due to error: {:?} ... continuing.",
                        TOKEN_PATH, e
                    );
                    return Ok(BTreeMap::new());
                }
            };
        }
    };
    let reader = BufReader::new(file);

    // Else try to read
    serde_json::from_reader(reader).map_err(|e| {
        error!(
            "JSON/IO error reading tokens from {:?} -> {:?}",
            &token_path, e
        );
    })
}

#[allow(clippy::result_unit_err)]
pub fn write_tokens(tokens: &BTreeMap<String, String>) -> Result<(), ()> {
    let token_dir = PathBuf::from(shellexpand::tilde(TOKEN_DIR).into_owned());
    let token_path = PathBuf::from(shellexpand::tilde(TOKEN_PATH).into_owned());

    token_dir
        .parent()
        .ok_or_else(|| {
            error!(
                "Parent directory to {} is invalid (root directory?).",
                TOKEN_DIR
            );
        })
        .and_then(|parent_dir| {
            if parent_dir.exists() {
                Ok(())
            } else {
                error!("Parent directory to {} does not exist.", TOKEN_DIR);
                Err(())
            }
        })?;

    if !token_dir.exists() {
        create_dir(token_dir).map_err(|e| {
            error!("Unable to create directory - {} {:?}", TOKEN_DIR, e);
        })?;
    }

    // Take away group/everyone read/write
    #[cfg(target_family = "unix")]
    let before = unsafe { umask(0o177) };

    let file = File::create(&token_path).map_err(|e| {
        #[cfg(target_family = "unix")]
        let _ = unsafe { umask(before) };
        error!("Can not write to {} -> {:?}", TOKEN_PATH, e);
    })?;

    #[cfg(target_family = "unix")]
    let _ = unsafe { umask(before) };

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, tokens).map_err(|e| {
        error!(
            "JSON/IO error writing tokens to file {:?} -> {:?}",
            &token_path, e
        );
    })
}

/// An interactive dialog to choose from given options
fn get_index_choice_dialoguer(msg: &str, options: &[String]) -> usize {
    let user_select = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(msg)
        .default(0)
        .items(options)
        .interact();

    let selection = match user_select {
        Err(error) => {
            error!("Failed to handle user input: {:?}", error);
            std::process::exit(1);
        }
        Ok(value) => value,
    };
    debug!("Index of the chosen menu item: {:?}", selection);

    selection
}

impl LoginOpt {
    pub fn debug(&self) -> bool {
        self.copt.debug
    }

    fn do_password(&self, client: &mut KanidmClient) -> Result<AuthResponse, ClientError> {
        let password = rpassword::prompt_password_stderr("Enter password: ").unwrap_or_else(|e| {
            error!("Failed to create password prompt -- {:?}", e);
            std::process::exit(1);
        });
        client.auth_step_password(password.as_str())
    }

    fn do_backup_code(&self, client: &mut KanidmClient) -> Result<AuthResponse, ClientError> {
        print!("Enter Backup Code: ");
        // We flush stdout so it'll write the buffer to screen, continuing operation. Without it, the application halts.
        #[allow(clippy::unwrap_used)]
        io::stdout().flush().unwrap();
        let mut backup_code = String::new();
        loop {
            if let Err(e) = io::stdin().read_line(&mut backup_code) {
                error!("Failed to read from stdin -> {:?}", e);
                return Err(ClientError::SystemError);
            };
            if !backup_code.trim().is_empty() {
                break;
            };
        }
        client.auth_step_backup_code(backup_code.trim())
    }

    fn do_totp(&self, client: &mut KanidmClient) -> Result<AuthResponse, ClientError> {
        let totp = loop {
            print!("Enter TOTP: ");
            // We flush stdout so it'll write the buffer to screen, continuing operation. Without it, the application halts.
            if let Err(e) = io::stdout().flush() {
                error!("Somehow we failed to flush stdout: {:?}", e);
            };
            let mut buffer = String::new();
            if let Err(e) = io::stdin().read_line(&mut buffer) {
                error!("Failed to read from stdin -> {:?}", e);
                return Err(ClientError::SystemError);
            };

            let response = buffer.trim();
            match response.parse::<u32>() {
                Ok(i) => break i,
                Err(_) => eprintln!("Invalid Number"),
            };
        };
        client.auth_step_totp(totp)
    }

    fn do_webauthn(
        &self,
        client: &mut KanidmClient,
        pkr: RequestChallengeResponse,
    ) -> Result<AuthResponse, ClientError> {
        let mut wa = WebauthnAuthenticator::new(U2FHid::new());
        println!("Your authenticator will now flash for you to interact with it.");
        let auth = wa
            .do_authentication(client.get_origin(), pkr)
            .unwrap_or_else(|e| {
                error!("Failed to interact with webauthn device. -- {:?}", e);
                std::process::exit(1);
            });

        client.auth_step_webauthn_complete(auth)
    }

    pub fn exec(&self) {
        let mut client = self.copt.to_unauth_client();

        // TODO: remove this anon, nobody should do default anonymous
        let username = self.copt.username.as_deref().unwrap_or("anonymous");

        // What auth mechanisms exist?
        let mechs: Vec<_> = client
            .auth_step_init(username)
            .unwrap_or_else(|e| {
                error!("Error during authentication init phase: {:?}", e);
                std::process::exit(1);
            })
            .into_iter()
            .collect();

        let mech = match mechs.len() {
            0 => {
                error!("Error during authentication init phase: Server offered no authentication mechanisms");
                std::process::exit(1);
            }
            1 =>
            {
                #[allow(clippy::expect_used)]
                mechs
                    .get(0)
                    .expect("can not fail - bounds already checked.")
            }
            _ => {
                let mut options = Vec::new();
                for val in mechs.iter() {
                    options.push(val.to_string());
                }
                let msg = "Please choose how you want to authenticate:";
                let selection = get_index_choice_dialoguer(msg, &options);

                #[allow(clippy::expect_used)]
                mechs
                    .get(selection as usize)
                    .expect("can not fail - bounds already checked.")
            }
        };

        let mut allowed = client.auth_step_begin((*mech).clone()).unwrap_or_else(|e| {
            error!("Error during authentication begin phase: {:?}", e);
            std::process::exit(1);
        });

        // We now have the first auth state, so we can proceed until complete.
        loop {
            debug!("Allowed mechanisms -> {:?}", allowed);
            // What auth can proceed?
            let choice = match allowed.len() {
                0 => {
                    error!(
                        "Error during authentication phase: Server offered no method to proceed"
                    );
                    std::process::exit(1);
                }
                1 =>
                {
                    #[allow(clippy::expect_used)]
                    allowed
                        .get(0)
                        .expect("can not fail - bounds already checked.")
                }
                _ => {
                    let mut options = Vec::new();
                    for val in allowed.iter() {
                        options.push(val.to_string());
                    }
                    let msg = "Please choose what credential to provide:";
                    let selection = get_index_choice_dialoguer(msg, &options);

                    #[allow(clippy::expect_used)]
                    allowed
                        .get(selection as usize)
                        .expect("can not fail - bounds already checked.")
                }
            };

            let res = match choice {
                AuthAllowed::Anonymous => client.auth_step_anonymous(),
                AuthAllowed::Password => self.do_password(&mut client),
                AuthAllowed::BackupCode => self.do_backup_code(&mut client),
                AuthAllowed::Totp => self.do_totp(&mut client),
                AuthAllowed::Webauthn(chal) => self.do_webauthn(&mut client, chal.clone()),
            };

            // Now update state.
            let state = res
                .unwrap_or_else(|e| {
                    error!("Error in authentication phase: {:?}", e);
                    std::process::exit(1);
                })
                .state;

            // What auth state are we in?
            allowed = match &state {
                AuthState::Continue(allowed) => allowed.to_vec(),
                AuthState::Success(_token) => break,
                AuthState::Denied(reason) => {
                    error!("Authentication Denied: {:?}", reason);
                    std::process::exit(1);
                }
                _ => {
                    error!("Error in authentication phase: invalid authstate");
                    std::process::exit(1);
                }
            };
            // Loop again.
        }

        // Read the current tokens
        let mut tokens = read_tokens().unwrap_or_else(|_| {
            error!("Error retrieving authentication token store");
            std::process::exit(1);
        });
        // Add our new one
        match client.get_token() {
            Some(t) => tokens.insert(username.to_string(), t),
            None => {
                error!("Error retrieving client session");
                std::process::exit(1);
            }
        };

        // write them out.
        if write_tokens(&tokens).is_err() {
            error!("Error persisting authentication token store");
            std::process::exit(1);
        };

        // Success!
        println!("Login Success for {}", username);
    }
}

impl LogoutOpt {
    pub fn debug(&self) -> bool {
        self.debug
    }

    pub fn exec(&self) {
        // For now we just remove this from the token store.

        let mut _tmp_username = String::new();
        let username = match &self.username {
            Some(value) => value,
            None => {
                _tmp_username = match prompt_for_username_get_username() {
                    Ok(value) => value,
                    Err(msg) => {
                        error!("{}", msg);
                        std::process::exit(1);
                    }
                };
                &_tmp_username
            }
        };
        let mut tokens = read_tokens().unwrap_or_else(|_| {
            error!("Error retrieving authentication token store");
            std::process::exit(1);
        });

        // Remove our old one
        if tokens.remove(username).is_some() {
            // write them out.
            if let Err(_e) = write_tokens(&tokens) {
                error!("Error persisting authentication token store");
                std::process::exit(1);
            };
            println!("Removed session for {}", username);
        } else {
            println!("No sessions for {}", username);
        }
    }
}

impl SessionOpt {
    pub fn debug(&self) -> bool {
        match self {
            SessionOpt::List(dopt) | SessionOpt::Cleanup(dopt) => dopt.debug,
        }
    }

    fn read_valid_tokens() -> BTreeMap<String, (String, UserAuthToken)> {
        read_tokens()
            .unwrap_or_else(|_| {
                error!("Error retrieving authentication token store");
                std::process::exit(1);
            })
            .into_iter()
            .filter_map(|(u, t)| {
                let jwtu = JwsUnverified::from_str(&t)
                    .map_err(|e| {
                        error!(?e, "Unable to parse token from str");
                    })
                    .ok()?;

                jwtu.validate_embeded()
                    .map_err(|e| {
                        error!(?e, "Unable to verify token signature, may be corrupt");
                    })
                    .map(|jwt| {
                        let uat = jwt.inner;
                        (u, (t, uat))
                    })
                    .ok()
            })
            .collect()
    }

    pub fn exec(&self) {
        match self {
            SessionOpt::List(_) => {
                let tokens = Self::read_valid_tokens();
                for (_, uat) in tokens.values() {
                    println!("---");
                    println!("{}", uat);
                }
            }
            SessionOpt::Cleanup(_) => {
                let tokens = Self::read_valid_tokens();
                let start_len = tokens.len();

                let now = time::OffsetDateTime::now_utc();

                let tokens: BTreeMap<_, _> = tokens
                    .into_iter()
                    .filter_map(|(u, (t, uat))| {
                        if now >= uat.expiry {
                            //Expired
                            None
                        } else {
                            Some((u, t))
                        }
                    })
                    .collect();

                let end_len = tokens.len();

                if let Err(_e) = write_tokens(&tokens) {
                    error!("Error persisting authentication token store");
                    std::process::exit(1);
                };

                println!("Removed {} sessions", start_len - end_len);
            }
        }
    }
}
