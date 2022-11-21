use webauthn_authenticator_rs::u2fhid::U2FHid;

pub fn get_authenticator_backend() -> U2FHid {
    U2FHid::new()
}
