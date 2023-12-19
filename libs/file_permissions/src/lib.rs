#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
pub use windows::{diagnose_path, readonly};

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use unix::{diagnose_path, readonly};
