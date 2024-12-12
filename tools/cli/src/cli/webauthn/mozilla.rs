use webauthn_authenticator_rs::mozilla::MozillaAuthenticator;

pub fn get_authenticator_backend() -> MozillaAuthenticator {
    MozillaAuthenticator::default()
}
