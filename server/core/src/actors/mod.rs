//! This module contains the server's async tasks that are called from the various frontend
//! components to conduct operations. These are separated based on protocol versions and
//! if they are read or write transactions internally.

pub mod v1_read;
pub mod v1_scim;
pub mod v1_write;
