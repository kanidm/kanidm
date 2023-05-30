use std::ffi::CString;

use selinux::{kernel_support, label::back_end::File, label::Labeler, KernelSupport};

pub fn supported() -> bool {
    return !matches!(kernel_support(), KernelSupport::Unsupported);
}

pub fn get_labeler() -> Result<Labeler<File>, String> {
    if let Ok(v) = Labeler::new(&[], true) {
        Ok(v)
    } else {
        Err("Failed getting handle for SELinux labeling".to_string())
    }
}

pub fn do_setfscreatecon_for_path(
    path_raw: &String,
    labeler: &Labeler<File>,
) -> Result<(), String> {
    match labeler.look_up(&CString::new(path_raw.to_owned()).unwrap(), 0) {
        Ok(context) => {
            if let Err(_) = context.set_for_new_file_system_objects(true) {
                return Err("Failed setting creation context home directory path".to_string());
            }
            Ok(())
        }
        Err(_) => {
            return Err("Failed looking up default context for home directory path".to_string());
        }
    }
}
