use crate::config::Configuration;
use rustls::{internal::pemfile, NoClientAuth, PrivateKey, ServerConfig, TLSError};
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::sync::Arc;

pub fn setup_tls(config: &Configuration) -> Result<Option<ServerConfig>, TLSError> {
    match &config.tls_config {
        Some(tls_config) => {
            let mut cert_chain: Vec<rustls::Certificate> = Vec::new();

            cert_chain.extend(
                pemfile::certs(&mut BufReader::new(
                    File::open(&tls_config.ca).expect("couldn't open ca"),
                ))
                .expect("couldn't read ca"),
            );

            cert_chain.extend(
                pemfile::certs(&mut BufReader::new(
                    File::open(&tls_config.cert).expect("couldn't open cert"),
                ))
                .expect("couldn't read cert"),
            );

            let mut keyfile =
                BufReader::new(File::open(&tls_config.key).expect("couldn't open private key"));
            let mut keys: Vec<PrivateKey> = pemfile::pkcs8_private_keys(&mut keyfile)
                .or_else(|_| -> Result<_, ()> {
                    keyfile.seek(std::io::SeekFrom::Start(0)).unwrap();
                    Ok(pemfile::rsa_private_keys(&mut keyfile)?)
                })
                .expect("couldn't read private key");

            let key = keys.pop().expect("no private keys in private key file");

            let mut ssl_config = ServerConfig::new(Arc::new(NoClientAuth));
            ssl_config.set_single_cert(cert_chain, key)?;

            Ok(Some(ssl_config))
        }
        None => Ok(None),
    }
}
