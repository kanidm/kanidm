use futures::StreamExt;
use webauthn_authenticator_rs::{
    ctap2::CtapAuthenticator,
    transport::{AnyToken, AnyTransport, Transport, TokenEvent},
    ui::Cli,
};

static CLI: Cli = Cli {};

pub async fn get_authenticator_backend() -> CtapAuthenticator<'static, AnyToken, Cli> {
    let t = AnyTransport::new().await.unwrap();
    match t.watch().await {
        Ok(mut tokens) => {
            while let Some(event) = tokens.next().await {
                match event {
                    TokenEvent::Added(token) => {
                        let auth = CtapAuthenticator::new(token, &CLI).await;

                        if let Some(auth) = auth {
                            return auth;
                        }
                    }

                    TokenEvent::EnumerationComplete => {
                        info!("device enumeration completed without detecting a FIDO2 authenticator, connect one to authenticate!");
                    }

                    TokenEvent::Removed(_) => {}
                }
            }
        }
        Err(e) => panic!("Error: {e:?}"),
    }

    panic!("No authenticators available!");
}
