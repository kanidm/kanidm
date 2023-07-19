#[cfg_attr(target_os = "windows", path = "win10.rs")]
#[cfg_attr(not(target_os = "windows"), path = "transport.rs")]
mod backend;
use backend::get_authenticator_backend;

use webauthn_authenticator_rs::{AuthenticatorBackend, WebauthnAuthenticator};

/// Gets a [WebauthnAuthenticator] with an appropriate backend for the current platform:
///
/// * On Windows, this uses the platform WebAuthn API, available on Windows 10
///   build 1903 and later.
///
///   This supports BLE, NFC and USB tokens.
///
/// * On other platforms, this uses `webauthn-authenticator-rs`' `AnyTransport`.
///
///   In the default configuration, this supports NFC and USB tokens, but
///   doesn't work on Windows systems which have the platform WebAuthn API
///   available.
pub(crate) async fn get_authenticator() -> WebauthnAuthenticator<impl AuthenticatorBackend> {
    WebauthnAuthenticator::new(get_authenticator_backend().await)
}
