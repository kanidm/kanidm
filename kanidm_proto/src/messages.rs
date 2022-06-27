// User-facing output things

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// TODO: this should probably be in the kanidm crate
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleOutputMode {
    Text,
    JSON,
}
impl Default for ConsoleOutputMode {
    fn default() -> Self {
        ConsoleOutputMode::Text
    }
}

impl FromStr for ConsoleOutputMode {
    type Err = &'static str;
    /// This can be safely unwrap'd because it'll always return a default
    fn from_str(s: &str) -> Result<Self, &'static str> {
        match s {
            "json" => Ok(ConsoleOutputMode::JSON),
            "text" => Ok(ConsoleOutputMode::Text),
            _ => {
                eprintln!(
                    "Supplied output mode ({:?}) was invalid, defaulting to text",
                    s
                );
                Ok(ConsoleOutputMode::Text)
            }
        }
    }
}

impl From<String> for ConsoleOutputMode {
    fn from(input: String) -> Self {
        match ConsoleOutputMode::from_str(input.as_str()) {
            Ok(val) => val,
            Err(_) => Self::Text,
        }
    }
}

// TODO: should this go somewhere else
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageStatus {
    Failure,
    Success,
}

impl fmt::Display for MessageStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match *self {
            MessageStatus::Failure => f.write_str("failure"),
            MessageStatus::Success => f.write_str("success"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountChangeMessage {
    #[serde(skip_serializing)]
    pub output_mode: ConsoleOutputMode,
    pub action: String,
    pub result: String,
    pub status: MessageStatus,
    pub src_user: String,
    pub dest_user: String,
}

impl Default for AccountChangeMessage {
    fn default() -> Self {
        AccountChangeMessage {
            output_mode: ConsoleOutputMode::Text,
            action: String::from(""),
            result: String::from(""),
            status: MessageStatus::Success,
            src_user: String::from(""),
            dest_user: String::from(""),
        }
    }
}

/// This outputs in either JSON or Text depending on the output_mode setting
impl fmt::Display for AccountChangeMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.output_mode {
            ConsoleOutputMode::JSON => write!(
                f,
                "{}",
                serde_json::to_string(self).unwrap_or(format!("{:?}", self)) // if it fails to JSON serialize, just debug-dump it
            ),
            ConsoleOutputMode::Text => write!(
                f,
                "{} - {} for user {}: {}",
                self.status, self.action, self.dest_user, self.result,
            ),
        }
    }
}
