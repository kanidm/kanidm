#[cfg(not(any(target_os = "windows", feature = "webauthn-transport")))]
mod mozilla;
#[cfg(not(any(target_os = "windows", feature = "webauthn-transport")))]
use mozilla::get_authenticator_backend;

#[cfg(feature = "webauthn-transport")]
mod transport;
#[cfg(feature = "webauthn-transport")]
use transport::get_authenticator_backend;

#[cfg(all(not(feature = "webauthn-transport"), target_os = "windows"))]
mod win10;
#[cfg(all(not(feature = "webauthn-transport"), target_os = "windows"))]
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
