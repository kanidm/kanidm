use libc::{gid_t, uid_t};

pub fn get_current_uid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn get_effective_uid() -> uid_t {
    unsafe { libc::geteuid() }
}

pub fn get_current_gid() -> gid_t {
    unsafe { libc::getgid() }
}

pub fn get_effective_gid() -> gid_t {
    unsafe { libc::getegid() }
}
