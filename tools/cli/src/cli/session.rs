use crate::common::OpType;
use std::collections::BTreeMap;
use std::fs::{create_dir, File};
use std::io::{self, BufReader, BufWriter, ErrorKind, IsTerminal, Write};
use std::path::PathBuf;
use std::str::FromStr;

use compact_jwt::{JwsCompact, JwsEs256Verifier, JwsVerifier, JwtError};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Select;
use kanidm_client::{ClientError, KanidmClient};
use kanidm_proto::constants::CLIENT_TOKEN_CACHE;
use kanidm_proto::v1::{AuthAllowed, AuthResponse, AuthState, UserAuthToken};
#[cfg(target_family = "unix")]
use libc::umask;
use webauthn_authenticator_rs::prelude::RequestChallengeResponse;

use crate::common::prompt_for_username_get_username;
use crate::webauthn::get_authenticator;
use crate::{CommonOpt, LoginOpt, LogoutOpt, ReauthOpt, SessionOpt};

static TOKEN_DIR: &str = "~/.cache";

impl CommonOpt {
    fn get_token_cache_path(&self) -> String {
        match self.token_cache_path.clone() {
            None => CLIENT_TOKEN_CACHE.to_string(),
            Some(val) => val.clone(),
        }
    }
}

#[allow(clippy::result_unit_err)]
pub fn read_tokens(token_path: &str) -> Result<BTreeMap<String, String>, ()> {
    let token_path = PathBuf::from(shellexpand::tilde(token_path).into_owned());
    if !token_path.exists() {
        debug!(
            "Token cache file path {:?} does not exist, returning an empty token store.",
            token_path
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
                        token_path.display(),
                        e
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
pub fn write_tokens(tokens: &BTreeMap<String, String>, token_path: &str) -> Result<(), ()> {
    let token_dir = PathBuf::from(shellexpand::tilde(TOKEN_DIR).into_owned());
    let token_path = PathBuf::from(shellexpand::tilde(token_path).into_owned());

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
        error!("Can not write to {} -> {:?}", token_path.display(), e);
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

async fn do_password(
    client: &mut KanidmClient,
    password: &Option<String>,
) -> Result<AuthResponse, ClientError> {
    let password = match password {
        Some(password) => {
            trace!("User provided password directly, don't need to prompt.");
            password.to_owned()
        }
        None => rpassword::prompt_password("Enter password: ").unwrap_or_else(|e| {
            error!("Failed to create password prompt -- {:?}", e);
            std::process::exit(1);
        }),
    };
    client.auth_step_password(password.as_str()).await
}

async fn do_backup_code(client: &mut KanidmClient) -> Result<AuthResponse, ClientError> {
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
    client.auth_step_backup_code(backup_code.trim()).await
}

async fn do_totp(client: &mut KanidmClient) -> Result<AuthResponse, ClientError> {
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
    client.auth_step_totp(totp).await
}

async fn do_passkey(
    client: &mut KanidmClient,
    pkr: RequestChallengeResponse,
) -> Result<AuthResponse, ClientError> {
    let mut wa = get_authenticator();
    println!("If your authenticator is not attached, attach it now.");
    println!("Your authenticator will then flash/prompt for confirmation.");
    #[cfg(target_os = "macos")]
    println!("Note: TouchID is not currently supported on the CLI 🫤");
    let auth = wa
        .do_authentication(client.get_origin().clone(), pkr)
        .map(Box::new)
        .unwrap_or_else(|e| {
            error!("Failed to interact with webauthn device. -- {:?}", e);
            std::process::exit(1);
        });

    client.auth_step_passkey_complete(auth).await
}

async fn do_securitykey(
    client: &mut KanidmClient,
    pkr: RequestChallengeResponse,
) -> Result<AuthResponse, ClientError> {
    let mut wa = get_authenticator();
    println!("Your authenticator will now flash for you to interact with it.");
    let auth = wa
        .do_authentication(client.get_origin().clone(), pkr)
        .map(Box::new)
        .unwrap_or_else(|e| {
            error!("Failed to interact with webauthn device. -- {:?}", e);
            std::process::exit(1);
        });

    client.auth_step_securitykey_complete(auth).await
}

async fn process_auth_state(
    mut allowed: Vec<AuthAllowed>,
    mut client: KanidmClient,
    maybe_password: &Option<String>,
) {
    loop {
        debug!("Allowed mechanisms -> {:?}", allowed);
        // What auth can proceed?
        let choice = match allowed.len() {
            0 => {
                error!("Error during authentication phase: Server offered no method to proceed");
                std::process::exit(1);
            }
            1 =>
            {
                #[allow(clippy::expect_used)]
                allowed
                    .first()
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
                    .get(selection)
                    .expect("can not fail - bounds already checked.")
            }
        };

        let res = match choice {
            AuthAllowed::Anonymous => client.auth_step_anonymous().await,
            AuthAllowed::Password => do_password(&mut client, maybe_password).await,
            AuthAllowed::BackupCode => do_backup_code(&mut client).await,
            AuthAllowed::Totp => do_totp(&mut client).await,
            AuthAllowed::Passkey(chal) => do_passkey(&mut client, chal.clone()).await,
            AuthAllowed::SecurityKey(chal) => do_securitykey(&mut client, chal.clone()).await,
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
    let mut tokens = read_tokens(&client.get_token_cache_path()).unwrap_or_else(|_| {
        error!("Error retrieving authentication token store");
        std::process::exit(1);
    });

    // Add our new one
    let (spn, tonk) = match client.get_token().await {
        Some(t) => {
            let jwsc = match JwsCompact::from_str(&t) {
                Ok(j) => j,
                Err(err) => {
                    error!(?err, "Unable to parse token");
                    std::process::exit(1);
                }
            };

            let jws_verifier = if let Some(pub_jwk) = jwsc.get_jwk_pubkey() {
                match JwsEs256Verifier::try_from(pub_jwk) {
                    Ok(verifier) => verifier,
                    Err(err) => {
                        error!(?err, "Unable to configure jws verifier");
                        std::process::exit(1);
                    }
                }
            } else {
                error!("Unable to access token public key");
                std::process::exit(1);
            };

            let tonk = match jws_verifier.verify(&jwsc).and_then(|jws| {
                jws.from_json::<UserAuthToken>().map_err(|serde_err| {
                    error!(?serde_err);
                    JwtError::InvalidJwt
                })
            }) {
                Ok(uat) => uat,
                Err(err) => {
                    error!(?err, "Unable to verify token signature");
                    std::process::exit(1);
                }
            };

            let spn = tonk.spn;
            // Return the un-parsed token
            (spn, t)
        }
        None => {
            error!("Error retrieving client session");
            std::process::exit(1);
        }
    };

    tokens.insert(spn.clone(), tonk);

    // write them out.
    if write_tokens(&tokens, &client.get_token_cache_path()).is_err() {
        error!("Error persisting authentication token store");
        std::process::exit(1);
    };

    // Success!
    println!("Login Success for {}", spn);
}

impl LoginOpt {
    pub fn debug(&self) -> bool {
        self.copt.debug
    }

    pub async fn exec(&self) {
        let client = self.copt.to_unauth_client();
        let username = match self.copt.username.as_deref() {
            Some(val) => val,
            None => {
                error!("Please specify a username with -D <USERNAME> to login.");
                std::process::exit(1);
            }
        };

        // What auth mechanisms exist?
        let mechs: Vec<_> = client
            .auth_step_init(username)
            .await
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
                    .first()
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
                    .get(selection)
                    .expect("can not fail - bounds already checked.")
            }
        };

        let allowed = client
            .auth_step_begin((*mech).clone())
            .await
            .unwrap_or_else(|e| {
                error!("Error during authentication begin phase: {:?}", e);
                std::process::exit(1);
            });

        // We now have the first auth state, so we can proceed until complete.
        process_auth_state(allowed, client, &self.password).await;
    }
}

impl ReauthOpt {
    pub fn debug(&self) -> bool {
        self.copt.debug
    }

    pub async fn exec(&self) {
        let client = self.copt.to_client(OpType::Read).await;

        let allowed = client.reauth_begin().await.unwrap_or_else(|e| {
            error!("Error during reauthentication begin phase: {:?}", e);
            std::process::exit(1);
        });

        process_auth_state(allowed, client, &None).await;
    }
}

impl LogoutOpt {
    pub fn debug(&self) -> bool {
        self.copt.debug
    }

    pub async fn exec(&self) {
        let spn: String = if self.local_only {
            // For now we just remove this from the token store.
            let mut _tmp_username = String::new();
            match &self.copt.username {
                Some(value) => value.clone(),
                None => {
                    // check if we're in a tty
                    if std::io::stdin().is_terminal() {
                        match prompt_for_username_get_username(&self.copt.get_token_cache_path()) {
                            Ok(value) => value,
                            Err(msg) => {
                                error!("{}", msg);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        eprintln!("Not running in interactive mode and no username specified, can't continue!");
                        return;
                    }
                }
            }
        } else {
            let client = self.copt.to_client(OpType::Read).await;
            let token = match client.get_token().await {
                Some(t) => t,
                None => {
                    error!("Client token store is empty/corrupt");
                    std::process::exit(1);
                }
            };
            // Parse it for the username.

            if let Err(e) = client.logout().await {
                error!("Failed to logout - {:?}", e);
                std::process::exit(1);
            }

            // Server acked the logout, lets proceed with the local cleanup now.

            let jwsc = match JwsCompact::from_str(&token) {
                Ok(j) => j,
                Err(err) => {
                    error!(?err, "Unable to parse token");
                    std::process::exit(1);
                }
            };

            let jws_verifier = if let Some(pub_jwk) = jwsc.get_jwk_pubkey() {
                match JwsEs256Verifier::try_from(pub_jwk) {
                    Ok(verifier) => verifier,
                    Err(err) => {
                        error!(?err, "Unable to configure jws verifier");
                        std::process::exit(1);
                    }
                }
            } else {
                error!("Unable to access token public key");
                std::process::exit(1);
            };

            let uat = match jws_verifier.verify(&jwsc).and_then(|jws| {
                jws.from_json::<UserAuthToken>().map_err(|serde_err| {
                    error!(?serde_err);
                    JwtError::InvalidJwt
                })
            }) {
                Ok(uat) => uat,
                Err(e) => {
                    error!(?e, "Unable to verify token signature, may be corrupt");
                    std::process::exit(1);
                }
            };

            uat.spn
        };

        let mut tokens = read_tokens(&self.copt.get_token_cache_path()).unwrap_or_else(|_| {
            error!("Error retrieving authentication token store");
            std::process::exit(1);
        });

        // Remove our old one
        if tokens.remove(&spn).is_some() {
            // write them out.
            if let Err(_e) = write_tokens(&tokens, &self.copt.get_token_cache_path()) {
                error!("Error persisting authentication token store");
                std::process::exit(1);
            };
            println!("Removed session for {}", spn);
        } else {
            println!("No sessions for {}", spn);
        }
    }
}

impl SessionOpt {
    pub fn debug(&self) -> bool {
        match self {
            SessionOpt::List(dopt) | SessionOpt::Cleanup(dopt) => dopt.debug,
        }
    }

    fn read_valid_tokens(token_cache_path: &str) -> BTreeMap<String, (String, UserAuthToken)> {
        read_tokens(token_cache_path)
            .unwrap_or_else(|_| {
                error!("Error retrieving authentication token store");
                std::process::exit(1);
            })
            .into_iter()
            .filter_map(|(u, t)| {
                let jwsc = JwsCompact::from_str(&t)
                    .map_err(|e| {
                        error!(?e, "Unable to parse token from str");
                    })
                    .ok()?;

                let jws_verifier = jwsc.get_jwk_pubkey().and_then(|pub_jwk| {
                    JwsEs256Verifier::try_from(pub_jwk)
                        .map_err(|e| {
                            error!(?e, "Unable to configure jws verifier");
                        })
                        .ok()
                })?;

                jws_verifier
                    .verify(&jwsc)
                    .and_then(|jws| {
                        jws.from_json::<UserAuthToken>().map_err(|serde_err| {
                            error!(?serde_err);
                            JwtError::InvalidJwt
                        })
                    })
                    .map_err(|e| {
                        error!(?e, "Unable to verify token signature, may be corrupt");
                    })
                    .map(|uat| (u, (t, uat)))
                    .ok()
            })
            .collect()
    }

    pub async fn exec(&self) {
        match self {
            SessionOpt::List(copt) => {
                let tokens = Self::read_valid_tokens(&copt.get_token_cache_path());
                for (_, uat) in tokens.values() {
                    println!("---");
                    println!("{}", uat);
                }
            }
            SessionOpt::Cleanup(copt) => {
                let tokens = Self::read_valid_tokens(&copt.get_token_cache_path());
                let start_len = tokens.len();

                let now = time::OffsetDateTime::now_utc();

                let tokens: BTreeMap<_, _> = tokens
                    .into_iter()
                    .filter_map(|(u, (t, uat))| {
                        if let Some(exp) = uat.expiry {
                            if now >= exp {
                                //Expired
                                None
                            } else {
                                Some((u, t))
                            }
                        } else {
                            Some((u, t))
                        }
                    })
                    .collect();

                let end_len = tokens.len();

                if let Err(_e) = write_tokens(&tokens, &copt.get_token_cache_path()) {
                    error!("Error persisting authentication token store");
                    std::process::exit(1);
                };

                println!("Removed {} sessions", start_len - end_len);
            }
        }
    }
}
