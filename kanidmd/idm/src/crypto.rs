//! This module contains cryptographic setup code, a long with what policy
//! and ciphers we accept.

use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};

use crate::config::Configuration;

/// From the server configuration, generate an OpenSSL acceptor that we can use
/// to build our sockets for https/ldaps.
pub fn setup_tls(config: &Configuration) -> Result<Option<SslAcceptorBuilder>, ErrorStack> {
    match &config.tls_config {
        Some(tls_config) => {
            let mut ssl_builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
            ssl_builder.set_certificate_chain_file(&tls_config.chain)?;
            ssl_builder.set_private_key_file(&tls_config.key, SslFiletype::PEM)?;
            ssl_builder.check_private_key()?;
            Ok(Some(ssl_builder))
        }
        None => Ok(None),
    }
}
