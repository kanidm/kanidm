#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
enum CpuOptLevel {
    none,
    native,
    x86_64_v1,
    x86_64_v3,
}

impl std::fmt::Display for CpuOptLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            CpuOptLevel::none => write!(f, "none"),
            CpuOptLevel::native => write!(f, "native"),
            CpuOptLevel::x86_64_v1 => write!(f, "x86_64_v1"),
            CpuOptLevel::x86_64_v3 => write!(f, "x86_64_v3"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProfileConfig {
    web_ui_pkg_path: String,
    cpu_flags: CpuOptLevel,
}

