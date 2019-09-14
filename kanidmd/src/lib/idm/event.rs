use crate::event::Event;
use uuid::Uuid;

#[derive(Debug)]
pub struct PasswordChangeEvent {
    pub event: Event,
    pub target: Uuid,
    pub cleartext: String,
    pub appid: Option<String>,
}

impl PasswordChangeEvent {
    pub fn new_internal(target: &Uuid, cleartext: &str, appid: Option<&str>) -> Self {
        PasswordChangeEvent {
            event: Event::from_internal(),
            target: target.clone(),
            cleartext: cleartext.to_string(),
            appid: appid.map(|v| v.to_string()),
        }
    }
}
