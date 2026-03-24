use crate::KanidmRadiusConfig;
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONTAINER_CONFIG_FILE_PATH: &str = "/data/radius.toml";
const USER_CONFIG_FILE_PATH: &str = ".config/radius.toml";
const SYSTEM_CONFIG_FILE_PATH: &str = "/etc/kanidm/radius.toml";
const EXAMPLE_CONFIG_FILE_PATH: &str = "../examples/radius.toml";
const LEGACY_CONFIG_FILE_PATH: &str = "/data/kanidm";
const CLIENTS_CONF_PATH: &str = "/etc/raddb/clients.conf";
const CERTS_DIR_PATH: &str = "/etc/raddb/certs";
const CERT_CA_DEST_PATH: &str = "/etc/raddb/certs/ca.pem";
const CERT_SERVER_DEST_PATH: &str = "/etc/raddb/certs/server.pem";
const FREERADIUS_BINARIES: [&str; 2] = ["/usr/sbin/radiusd", "/usr/sbin/freeradius"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapLayout {
    pub clients_conf: PathBuf,
    pub certs_dir: PathBuf,
    pub cert_ca_dest: PathBuf,
    pub cert_server_dest: PathBuf,
}

impl Default for BootstrapLayout {
    fn default() -> Self {
        Self {
            clients_conf: PathBuf::from(CLIENTS_CONF_PATH),
            certs_dir: PathBuf::from(CERTS_DIR_PATH),
            cert_ca_dest: PathBuf::from(CERT_CA_DEST_PATH),
            cert_server_dest: PathBuf::from(CERT_SERVER_DEST_PATH),
        }
    }
}

pub fn discover_config_path(config_override: Option<&Path>) -> Option<PathBuf> {
    build_config_search_paths(config_override)
        .into_iter()
        .find(|path| path.exists())
}

pub fn build_config_search_paths(config_override: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(path) = config_override {
        paths.push(path.to_path_buf());
    }

    paths.push(PathBuf::from(CONTAINER_CONFIG_FILE_PATH));

    if let Some(home_dir) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home_dir).join(USER_CONFIG_FILE_PATH));
    }

    paths.push(PathBuf::from(SYSTEM_CONFIG_FILE_PATH));
    paths.push(PathBuf::from(EXAMPLE_CONFIG_FILE_PATH));
    paths.push(PathBuf::from(LEGACY_CONFIG_FILE_PATH));

    paths
}

pub fn load_radius_config(config_path: &Path) -> Result<KanidmRadiusConfig> {
    let config_text = fs::read_to_string(config_path).with_context(|| {
        format!(
            "failed to read configuration file {}",
            config_path.display()
        )
    })?;
    toml::from_str(&config_text).with_context(|| {
        format!(
            "failed to parse configuration file {}",
            config_path.display()
        )
    })
}

pub fn write_clients_conf(config: &KanidmRadiusConfig, clients_conf_path: &Path) -> Result<()> {
    let mut rendered = String::new();

    for client in &config.radius_clients {
        rendered.push_str(&format!("client {} {{\n", client.name));
        rendered.push_str(&format!("    ipaddr = {}\n", client.ipaddr));
        rendered.push_str(&format!("    secret = {}\n", client.secret));
        rendered.push_str("    require_message_authenticator = yes\n");
        rendered.push_str("    proto = *\n");
        rendered.push_str("}\n");
    }

    fs::write(clients_conf_path, rendered).with_context(|| {
        format!(
            "failed to write clients.conf to {}",
            clients_conf_path.display()
        )
    })
}

pub fn prepare_certs(config: &KanidmRadiusConfig, layout: &BootstrapLayout) -> Result<()> {
    fs::create_dir_all(&layout.certs_dir).with_context(|| {
        format!(
            "failed to create certificate directory {}",
            layout.certs_dir.display()
        )
    })?;

    if let Some(radius_ca_path) = &config.radius_ca_path {
        let ca_source = resolve_existing_file(radius_ca_path, "radius CA file")?;
        copy_file(&ca_source, &layout.cert_ca_dest)?;
    }

    if let Some(radius_ca_dir) = &config.radius_ca_dir {
        let ca_dir_source = resolve_existing_dir(radius_ca_dir, "radius CA directory")?;
        copy_dir_recursive(&ca_dir_source, &layout.certs_dir)?;
    }

    rehash_certificates(&layout.certs_dir)?;

    let cert_source = resolve_existing_file(&config.radius_cert_path, "server certificate")?;
    let key_source = resolve_existing_file(&config.radius_key_path, "server key")?;
    write_server_pem(&cert_source, &key_source, &layout.cert_server_dest)
}

pub fn find_freeradius_bin() -> Option<PathBuf> {
    FREERADIUS_BINARIES
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

pub fn run(config_override: Option<&Path>, debug: bool) -> Result<()> {
    let config_path = discover_config_path(config_override).ok_or_else(|| {
        anyhow!(
            "failed to find configuration file in ({})",
            render_search_paths(&build_config_search_paths(config_override))
        )
    })?;

    let config = load_radius_config(&config_path)?;
    let layout = BootstrapLayout::default();
    write_clients_conf(&config, &layout.clients_conf)?;
    prepare_certs(&config, &layout)?;

    eprintln!("Configuration set up, starting FreeRADIUS");
    exec_radiusd(debug)
}

fn render_search_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn resolve_existing_file(path: &str, label: &str) -> Result<PathBuf> {
    let resolved = PathBuf::from(path);
    if !resolved.is_file() {
        bail!("failed to find {label} ({})", resolved.display());
    }
    Ok(resolved)
}

fn resolve_existing_dir(path: &str, label: &str) -> Result<PathBuf> {
    let resolved = PathBuf::from(path);
    if !resolved.is_dir() {
        bail!("failed to find {label} ({})", resolved.display());
    }
    Ok(resolved)
}

fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        return Ok(());
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create parent directory for {}",
                destination.display()
            )
        })?;
    }

    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).with_context(|| {
        format!(
            "failed to create destination directory {}",
            destination.display()
        )
    })?;

    for entry in fs::read_dir(source)
        .with_context(|| format!("failed to read directory {}", source.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to iterate directory {}", source.display()))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().with_context(|| {
            format!(
                "failed to determine file type for {}",
                source_path.display()
            )
        })?;

        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            copy_file(&source_path, &destination_path)?;
        } else if file_type.is_symlink() {
            let target = fs::canonicalize(&source_path)
                .with_context(|| format!("failed to resolve symlink {}", source_path.display()))?;
            if target.is_dir() {
                copy_dir_recursive(&target, &destination_path)?;
            } else {
                copy_file(&target, &destination_path)?;
            }
        }
    }

    Ok(())
}

fn rehash_certificates(certs_dir: &Path) -> Result<()> {
    let status = Command::new("openssl")
        .arg("rehash")
        .arg(certs_dir)
        .status()
        .with_context(|| format!("failed to execute openssl rehash {}", certs_dir.display()))?;

    if !status.success() {
        bail!("openssl rehash failed for {}", certs_dir.display());
    }

    Ok(())
}

fn write_server_pem(cert_source: &Path, key_source: &Path, server_pem_dest: &Path) -> Result<()> {
    let cert_contents = fs::read(cert_source).with_context(|| {
        format!(
            "failed to read server certificate {}",
            cert_source.display()
        )
    })?;
    let key_contents = fs::read(key_source)
        .with_context(|| format!("failed to read server key {}", key_source.display()))?;

    let mut pem = Vec::with_capacity(cert_contents.len() + key_contents.len() + 1);
    pem.extend_from_slice(&cert_contents);
    if !pem.ends_with(b"\n") {
        pem.push(b'\n');
    }
    pem.extend_from_slice(&key_contents);

    let mut output = fs::File::create(server_pem_dest)
        .with_context(|| format!("failed to create {}", server_pem_dest.display()))?;
    output
        .write_all(&pem)
        .with_context(|| format!("failed to write {}", server_pem_dest.display()))?;
    Ok(())
}

fn exec_radiusd(debug: bool) -> Result<()> {
    let freeradius_bin = find_freeradius_bin().ok_or_else(|| {
        anyhow!(
            "failed to find FreeRADIUS binary, looked in {}",
            FREERADIUS_BINARIES.join(", ")
        )
    })?;

    let args = if debug {
        vec![OsString::from("-X")]
    } else {
        vec![
            OsString::from("-f"),
            OsString::from("-l"),
            OsString::from("stdout"),
        ]
    };

    let err = Command::new(&freeradius_bin).args(&args).exec();
    Err(anyhow!(
        "failed to exec {}: {err}",
        freeradius_bin.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rlm-kanidm-bootstrap-{}-{}-{}",
                std::process::id(),
                nanos,
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn config_path_selection_prefers_first_existing_candidate() {
        let tmp = TestTempDir::new();
        let missing = tmp.path().join("missing.toml");
        let selected = tmp.path().join("selected.toml");
        fs::write(
            &selected,
            "uri = \"https://example.com\"\nauth_token = \"token\"\n",
        )
        .expect("failed to write config file");

        let discovered = vec![missing, selected.clone()]
            .into_iter()
            .find(|path| path.exists())
            .expect("expected config to be discovered");

        assert_eq!(discovered, selected);
    }

    #[test]
    fn write_clients_conf_renders_message_authenticator_and_proto() {
        let tmp = TestTempDir::new();
        let clients_conf = tmp.path().join("clients.conf");
        let config = KanidmRadiusConfig {
            radius_clients: vec![crate::RadiusClientConfig {
                name: "localhost".to_string(),
                ipaddr: "127.0.0.1".to_string(),
                secret: "radius-secret".to_string(),
            }],
            ..KanidmRadiusConfig::default()
        };

        write_clients_conf(&config, &clients_conf).expect("failed to write clients.conf");

        let rendered = fs::read_to_string(clients_conf).expect("failed to read clients.conf");
        assert!(rendered.contains("client localhost {"));
        assert!(rendered.contains("require_message_authenticator = yes"));
        assert!(rendered.contains("proto = *"));
    }

    #[test]
    fn write_server_pem_concatenates_cert_and_key() {
        let tmp = TestTempDir::new();
        let cert = tmp.path().join("cert.pem");
        let key = tmp.path().join("key.pem");
        let server_pem = tmp.path().join("server.pem");

        fs::write(&cert, "CERTIFICATE").expect("failed to write cert");
        fs::write(&key, "PRIVATE KEY").expect("failed to write key");

        write_server_pem(&cert, &key, &server_pem).expect("failed to write server.pem");

        let pem = fs::read_to_string(server_pem).expect("failed to read server.pem");
        assert_eq!(pem, "CERTIFICATE\nPRIVATE KEY");
    }

    #[test]
    fn prepare_certs_fails_when_server_material_is_missing() {
        let tmp = TestTempDir::new();
        let layout = BootstrapLayout {
            clients_conf: tmp.path().join("clients.conf"),
            certs_dir: tmp.path().join("certs"),
            cert_ca_dest: tmp.path().join("certs/ca.pem"),
            cert_server_dest: tmp.path().join("certs/server.pem"),
        };
        let config = KanidmRadiusConfig {
            radius_cert_path: tmp.path().join("missing-cert.pem").display().to_string(),
            radius_key_path: tmp.path().join("missing-key.pem").display().to_string(),
            ..KanidmRadiusConfig::default()
        };

        let error = prepare_certs(&config, &layout).expect_err("expected cert setup to fail");
        assert!(error
            .to_string()
            .contains("failed to find server certificate"));
    }
}
