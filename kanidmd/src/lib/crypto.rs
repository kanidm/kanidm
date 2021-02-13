use crate::config::Configuration;
use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};

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
