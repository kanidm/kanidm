use crate::event::Event;

#[derive(Debug)]
pub struct PasswordChangeEvent {
    pub event: Event,
    pub cleartext: String,
    pub appid: Option<String>,
}

impl PasswordChangeEvent {
}
