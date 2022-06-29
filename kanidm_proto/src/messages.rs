// User-facing output things

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// This is used in user-facing CLIs to set the formatting for output,
/// and defaults to text.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
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
    /// This can be safely unwrap'd because it'll always return a default of text
    /// ```
    /// use kanidm_proto::messages::ConsoleOutputMode;
    ///
    /// let mode: ConsoleOutputMode = "🦀".into();
    /// assert_eq!(ConsoleOutputMode::Text, mode);
    ///
    /// let mode: ConsoleOutputMode = "json".into();
    /// assert_eq!(ConsoleOutputMode::JSON, mode);
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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

/// This will take any string, if it's 'text' or 'json' then you'll get
/// what you asked for, else you'll get a text version.
///
/// ```
/// use kanidm_proto::messages::ConsoleOutputMode;
/// let bork = "text";
/// let com: ConsoleOutputMode = bork.into();
/// matches!(ConsoleOutputMode::Text, com);
/// ```
impl From<&str> for ConsoleOutputMode {
    fn from(input: &str) -> Self {
        match ConsoleOutputMode::from_str(input) {
            Ok(val) => val,
            Err(_) => Self::Text,
        }
    }
}

/// This will take any string, if it's 'text' or 'json' then you'll get
/// what you asked for, else you'll get a text version.
///
/// ```
/// use kanidm_proto::messages::ConsoleOutputMode;
/// let bork = String::from("cr4bz");
/// let com: ConsoleOutputMode = bork.into();
/// matches!(ConsoleOutputMode::Text, com);
/// ```
impl From<String> for ConsoleOutputMode {
    fn from(input: String) -> Self {
        match ConsoleOutputMode::from_str(input.as_str()) {
            Ok(val) => val,
            Err(_) => Self::Text,
        }
    }
}

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



#[derive(Debug, Serialize, Deserialize)]
pub struct BasicMessage {
    #[serde(skip_serializing)]
    pub output_mode: ConsoleOutputMode,
    pub action: String,
    pub result: String,
    pub status: MessageStatus,
}

impl Default for BasicMessage {
    fn default() -> Self {
        BasicMessage {
            output_mode: ConsoleOutputMode::Text,
            action: String::from(""),
            result: String::from(""),
            status: MessageStatus::Success,
        }
    }
}

/// This outputs in either JSON or Text depending on the output_mode setting
/// ```
/// use std::fmt::format;
/// use kanidm_proto::messages::*;
/// let mut msg = BasicMessage::default();
/// msg.action="cake_eating";
/// msg.result="It was amazing";
/// assert_eq!(msg.status, MessageStatus::Success);
///
/// let expected_result = "success - cake_eating: It was amazing";
/// assert_eq!(format!("{}", msg), expected_result);
/// // msg.output_mode = ConsoleOutputMode::JSON;
/// // let expected_result = "success - cake_eating: It was amazing";
/// // assert_eq!(format("{}", msg), expected_result);
///
/// ```
impl fmt::Display for BasicMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.output_mode {
            ConsoleOutputMode::JSON => write!(
                f,
                "{}",
                serde_json::to_string(self).unwrap_or(format!("{:?}", self)) // if it fails to JSON serialize, just debug-dump it
            ),
            ConsoleOutputMode::Text => write!(
                f,
                "{} - {}: {}",
                self.status, self.action, self.result,
            ),
        }
    }
}
