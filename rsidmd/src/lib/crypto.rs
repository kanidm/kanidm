
use crate::config::Configuration;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslFiletype};
use openssl::error::ErrorStack;

pub fn setup_tls(config: &Configuration) -> Result<Option<SslAcceptorBuilder>, ErrorStack> {
    match &config.tls_config {
        Some(tls_config) => {
            let mut ssl_builder =
                SslAcceptor::mozilla_modern(SslMethod::tls())?;
            ssl_builder.set_ca_file(&tls_config.ca)?;
            ssl_builder
                .set_private_key_file(&tls_config.key, SslFiletype::PEM)?;
            ssl_builder
                .set_certificate_file(&tls_config.cert, SslFiletype::PEM)?;
            ssl_builder.check_private_key()?;
            Ok(Some(ssl_builder))
        }
        None => Ok(None)
    }
}

