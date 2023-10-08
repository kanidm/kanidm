use std::time::{Duration, SystemTime};

pub fn duration_from_epoch_now() -> Duration {
    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("invalid duration from epoch now")
}
