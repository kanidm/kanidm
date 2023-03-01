use std::error::Error;
use std::fmt;

use wasm_bindgen::JsValue;

#[derive(Debug, Clone, PartialEq)]
pub struct FetchError {
    err: JsValue,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.err, f)
    }
}

impl Error for FetchError {}

impl From<JsValue> for FetchError {
    fn from(value: JsValue) -> Self {
        Self { err: value }
    }
}

impl FetchError {
    pub fn as_string(&self) -> String {
        self.err.as_string().unwrap_or_else(|| "null".to_string())
    }
}
