use crate::common::CommonOpt;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use structopt::StructOpt;
use kanidm_client::{KanidmClient, ClientError};
use webauthn_authenticator_rs::{u2fhid::U2FHid, WebauthnAuthenticator};

static TOKEN_PATH: &str = "~/.cache/kanidm_tokens";

pub fn read_tokens() -> Result<BTreeMap<String, String>, ()> {
    let token_path: String = shellexpand::tilde(TOKEN_PATH).into_owned();
    // If the file does not exist, return Ok<map>
    let file = match File::open(token_path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Can not read from {}, continuing ... {:?}", TOKEN_PATH, e);
            return Ok(BTreeMap::new());
        }
    };
    let reader = BufReader::new(file);

    // Else try to read
    serde_json::from_reader(reader).map_err(|e| {
        error!("JSON/IO error -> {:?}", e);
    })
}

pub fn write_tokens(tokens: &BTreeMap<String, String>) -> Result<(), ()> {
    let token_path: String = shellexpand::tilde(TOKEN_PATH).into_owned();
    let file = File::create(token_path).map_err(|e| {
        error!("Can not write to {} -> {:?}", TOKEN_PATH, e);
    })?;

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, tokens).map_err(|e| {
        error!("JSON/IO error -> {:?}", e);
    })
}

#[derive(Debug, StructOpt)]
pub struct LoginOpt {
    #[structopt(flatten)]
    pub copt: CommonOpt,
    #[structopt(short = "w", long = "webauthn")]
    pub webauthn: bool,
}

impl LoginOpt {
    pub fn debug(&self) -> bool {
        self.copt.debug
    }

    fn do_password(&self, client: &mut KanidmClient, username: &str) -> (Result<(), ClientError>, String) {
        let password = match rpassword::prompt_password_stderr("Enter password: ") {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to create password prompt -- {:?}", e);
                std::process::exit(1);
            }
        };
        (
            client.auth_simple_password(username, password.as_str()),
            username.to_string(),
        )
    }

    fn do_webauthn(&self, client: &mut KanidmClient, username: &str) -> (Result<(), ClientError>, String) {
        let pkr = match client.auth_webauthn_begin(username) {
            Ok(pkr) => pkr,
            Err(e) => {
                error!("Failed to request webauthn challenge. -- {:?}", e);
                std::process::exit(1);
            }
        };

        let mut wa = WebauthnAuthenticator::new(U2FHid::new());
        println!("Your authenticator will now flash for you to interact with it.");
        let auth = match wa.do_authentication(client.get_origin(), pkr) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to interact with webauthn device. -- {:?}", e);
                std::process::exit(1);
            }
        };

        (
            client.auth_webauthn_complete(auth),
            username.to_string(),
        )
    }

    pub fn exec(&self) {
        let mut client = self.copt.to_unauth_client();

        let (r, username) = match self.copt.username.as_deref() {
            None | Some("anonymous") => (client.auth_anonymous(), "anonymous".to_string()),
            Some(username) => {
                if self.webauthn {
                    self.do_webauthn(&mut client, username)
                } else {
                    self.do_password(&mut client, username)
                }
            }
        };

        if r.is_err() {
            error!("Error during authentication phase: {:?}", r);
            std::process::exit(1);
        }

        // Read the current tokens
        let mut tokens = match read_tokens() {
            Ok(t) => t,
            Err(_e) => {
                error!("Error retrieving authentication token store");
                std::process::exit(1);
            }
        };
        // Add our new one
        match client.get_token() {
            Some(t) => tokens.insert(username.clone(), t.to_string()),
            None => {
                error!("Error retrieving client session");
                std::process::exit(1);
            }
        };

        // write them out.
        if let Err(_e) = write_tokens(&tokens) {
            error!("Error persisting authentication token store");
            std::process::exit(1);
        };

        // Success!
        println!("Login Success for {}", username);
    }
}
