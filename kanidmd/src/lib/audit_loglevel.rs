use std::str::FromStr;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(u32)]
pub enum LogLevel {
    // Errors only
    Quiet = 0x0000_1111,
    // All Error, All Security, Request and Admin Warning,
    Default = 0x0000_1111 | 0x0000_0f00 | 0x0000_0022 | 0x1000_0000,
    // Default + Filter Plans
    Filter = 0x0000_1111 | 0x0000_0f00 | 0x0000_0022 | 0x0000_4000 | 0x1000_0000,
    // All Error, All Warning, All Info, Filter and Request Tracing
    Verbose = 0x0000_ffff | 0x1000_0000,
    // Default + PerfCoarse
    PerfBasic = 0x0000_1111 | 0x0000_0f00 | 0x0000_0022 | 0x3000_0000,
    // Default + PerfCoarse ? PerfTrace
    PerfFull = 0x0000_1111 | 0x0000_0f00 | 0x0000_0022 | 0x7000_0000,
    // Yolo
    FullTrace = 0xffff_ffff,
}

impl FromStr for LogLevel {
    type Err = &'static str;
    fn from_str(l: &str) -> Result<Self, Self::Err> {
        match l.to_lowercase().as_str() {
            "quiet" => Ok(LogLevel::Quiet),
            "default" => Ok(LogLevel::Default),
            "filter" => Ok(LogLevel::Filter),
            "verbose" => Ok(LogLevel::Verbose),
            "perfbasic" => Ok(LogLevel::PerfBasic),
            "perffull" => Ok(LogLevel::PerfFull),
            "fulltrace" => Ok(LogLevel::FullTrace),
            _ => Err("Could not parse loglevel"),
        }
    }
}
