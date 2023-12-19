use filetime::FileTime;
use std::fs::File;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::SystemTime;

pub fn touch_file_or_quit(file_path: &str) {
    /*
    Attempt to touch the file file_path, will quit the application if it fails for any reason.

    Will also create a new file if it doesn't already exist.
    */
    if PathBuf::from(file_path).exists() {
        let t = FileTime::from_system_time(SystemTime::now());
        match filetime::set_file_times(file_path, t, t) {
            Ok(_) => debug!(
                "Successfully touched existing file {}, can continue",
                file_path
            ),
            Err(e) => {
                match e.kind() {
                    ErrorKind::PermissionDenied => {
                        // we bail here because you won't be able to write them back...
                        error!("Permission denied writing to {}, quitting.", file_path)
                    }
                    _ => {
                        error!(
                            "Failed to write to {} due to error: {:?} ... quitting.",
                            file_path, e
                        )
                    }
                }
                std::process::exit(1);
            }
        }
    } else {
        match File::create(file_path) {
            Ok(_) => debug!("Successfully touched new file {}", file_path),
            Err(e) => {
                error!(
                    "Failed to write to {} due to error: {:?} ... quitting.",
                    file_path, e
                );
                std::process::exit(1);
            }
        };
    }
}
