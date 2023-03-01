#[cfg(not(any(target_os = "windows")))]
mod mozilla;
#[cfg(not(any(target_os = "windows")))]
use mozilla::get_authenticator_backend;

#[cfg(target_os = "windows")]
mod win10;
#[cfg(target_os = "windows")]
use win10::get_authenticator_backend;

use webauthn_authenticator_rs::{AuthenticatorBackend, WebauthnAuthenticator};

/// Gets a [WebauthnAuthenticator] with an appropriate backend for the current platform:
///
/// * On Windows, this uses the platform WebAuthn API, available on Windows 10
///   build 1903 and later.
///
///   This supports BLE, NFC and USB tokens.
///
/// * On other platforms, this uses Mozilla's `authenticator-rs`.
///
///   This only supports USB tokens, and doesn't work on Windows systems which
///   have the platform WebAuthn API available.
pub(crate) fn get_authenticator() -> WebauthnAuthenticator<impl AuthenticatorBackend> {
    WebauthnAuthenticator::new(get_authenticator_backend())
}
