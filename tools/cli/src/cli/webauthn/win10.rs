use webauthn_authenticator_rs::win10::Win10;

pub async fn get_authenticator_backend() -> Win10 {
    Default::default()
}
