use webauthn_authenticator_rs::{
    ctap2::CtapAuthenticator,
    transport::{AnyToken, AnyTransport, Transport},
    ui::Cli,
};

static CLI: Cli = Cli {};

pub fn get_authenticator_backend() -> CtapAuthenticator<'static, AnyToken, Cli> {
    let mut t = AnyTransport::new().unwrap();
    t.connect_one(&CLI).unwrap()
}
