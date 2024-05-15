#![deny(warnings)]
#![warn(unused_extern_crates)]
#![allow(non_snake_case)]
use std::fmt::Display;
use std::str::FromStr;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::Deserialize;
use serde::Serialize;
use tracing_forest::printer::TestCapturePrinter;
use tracing_forest::tag::NoTag;
use tracing_forest::util::*;
use tracing_forest::Tag;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::prelude::*;

pub mod macros;
pub mod otel;

pub use {tracing, tracing_forest, tracing_subscriber};

/// Start up the logging for test mode.
pub fn test_init() {
    let filter = EnvFilter::builder()
        // Skipping trace on tests by default saves a *TON* of ram.
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        // escargot builds cargo packages while we integration test and is SUPER noisy.
        .add_directive(
            "escargot=ERROR"
                .parse()
                .expect("failed to generate log filter"),
        )
        // hyper's very noisy in debug mode with connectivity-related things that we only need in extreme cases.
        .add_directive("hyper=INFO".parse().expect("failed to generate log filter"));

    // start the logging!
    let _ = tracing_subscriber::Registry::default()
        .with(ForestLayer::new(TestCapturePrinter::new(), NoTag).with_filter(filter))
        .try_init();
}

/// This is for tagging events. Currently not wired in.
pub fn event_tagger(_event: &Event) -> Option<Tag> {
    None
}

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u64)]
pub enum EventTag {
    AdminDebug,
    AdminError,
    AdminWarn,
    AdminInfo,
    RequestError,
    RequestWarn,
    RequestInfo,
    RequestTrace,
    SecurityCritical,
    SecurityDebug,
    SecurityInfo,
    SecurityAccess,
    SecurityError,
    FilterError,
    FilterWarn,
    FilterInfo,
    FilterTrace,
    PerfTrace,
}

impl EventTag {
    pub fn pretty(self) -> &'static str {
        match self {
            EventTag::AdminDebug => "admin.debug",
            EventTag::AdminError => "admin.error",
            EventTag::AdminWarn => "admin.warn",
            EventTag::AdminInfo => "admin.info",
            EventTag::RequestError => "request.error",
            EventTag::RequestWarn => "request.warn",
            EventTag::RequestInfo => "request.info",
            EventTag::RequestTrace => "request.trace",
            EventTag::SecurityCritical => "security.critical",
            EventTag::SecurityDebug => "security.debug",
            EventTag::SecurityInfo => "security.info",
            EventTag::SecurityAccess => "security.access",
            EventTag::SecurityError => "security.error",
            EventTag::FilterError => "filter.error",
            EventTag::FilterWarn => "filter.warn",
            EventTag::FilterInfo => "filter.info",
            EventTag::FilterTrace => "filter.trace",
            EventTag::PerfTrace => "perf.trace",
        }
    }

    pub fn emoji(self) -> &'static str {
        use EventTag::*;
        match self {
            AdminDebug | SecurityDebug => "🐛",
            AdminError | FilterError | RequestError | SecurityError => "🚨",
            AdminWarn | FilterWarn | RequestWarn => "⚠️",
            AdminInfo | FilterInfo | RequestInfo | SecurityInfo => "ℹ️",
            RequestTrace | FilterTrace | PerfTrace => "📍",
            SecurityCritical => "🔐",
            SecurityAccess => "🔓",
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, Default)]
pub enum LogLevel {
    #[default]
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "debug")]
    Debug,
    #[serde(rename = "trace")]
    Trace,
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Err("Must be one of info, debug, trace"),
        }
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        })
    }
}

impl From<LogLevel> for Directive {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Info => Directive::from(Level::INFO),
            LogLevel::Debug => Directive::from(Level::DEBUG),
            LogLevel::Trace => Directive::from(Level::TRACE),
        }
    }
}
