use std::str::FromStr;

use clap::{builder::PossibleValue, ValueEnum};
use serde::Deserialize;

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum OpType {
    Read,
    Write,
}

impl FromStr for OpType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "read" => Ok(OpType::Read),
            "write" => Ok(OpType::Write),
            _ => Err(format!("Invalid OpType: {}", s)),
        }
    }
}

impl ValueEnum for OpType {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Read, Self::Write]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::from(self.as_str()))
    }
}

impl OpType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OpType::Read => "read",
            OpType::Write => "write",
        }
    }
}
