use anyhow::{anyhow, bail, Context, Result};
use rlm_kanidm_shared::config::KanidmRadiusConfig;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONTAINER_CONFIG_FILE_PATH: &str = "/data/radius.toml";

const CLIENTS_CONF_PATH: &str = "/etc/raddb/clients.conf";
const CERTS_DIR_PATH: &str = "/etc/raddb/certs";
const CERT_CA_DEST_PATH: &str = "/etc/raddb/certs/ca.pem";
const CERT_SERVER_DEST_PATH: &str = "/etc/raddb/certs/server.pem";
const FREERADIUS_EXEC: &str = "/usr/sbin/radiusd";

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

pub fn write_clients_conf<O: Write>(
    config: &KanidmRadiusConfig,
    output: &mut O,
) -> std::io::Result<()> {
    let mut rendered = String::new();

    for client in &config.radius_clients {
        rendered.push_str(&format!("client {} {{\n", client.name));
        rendered.push_str(&format!("    ipaddr = {}\n", client.ipaddr));
        rendered.push_str(&format!("    secret = {}\n", client.secret));
        rendered.push_str("    require_message_authenticator = yes\n");
        rendered.push_str("    proto = *\n");
        rendered.push_str("}\n");
    }

    output.write_all(rendered.as_bytes())
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
        fs::copy(&ca_source, &layout.cert_ca_dest)?;
    }

    if let Some(radius_ca_dir) = &config.radius_ca_dir {
        let ca_dir_source = resolve_existing_dir(radius_ca_dir, "radius CA directory")?;
        copy_dir(&ca_dir_source, &layout.certs_dir)?;
        // Only the CA dir needs rehash
        rehash_certificates(radius_ca_dir.as_ref())?;
    }

    let cert_source = resolve_existing_file(&config.radius_cert_path, "server certificate")?;
    let key_source = resolve_existing_file(&config.radius_key_path, "server key")?;

    let mut cert_source_file = fs::File::open(&cert_source).with_context(|| {
        format!(
            "failed to read server certificate {}",
            cert_source.display()
        )
    })?;

    let mut key_source_file = fs::File::open(&key_source)
        .with_context(|| format!("failed to read server key {}", key_source.display()))?;

    let mut bundle_dest = fs::File::create(&layout.cert_server_dest).with_context(|| {
        format!(
            "failed to open server key bundle {}",
            layout.cert_server_dest.display()
        )
    })?;

    write_server_pem(
        &mut cert_source_file,
        &mut key_source_file,
        &mut bundle_dest,
    )
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

fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
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

        // Anything else will fail, it can't be valid in a container
        if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
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

fn write_server_pem<I: Read, O: Write>(
    cert_source: &mut I,
    key_source: &mut I,
    server_pem: &mut O,
) -> Result<()> {
    let mut buf = String::new();
    cert_source.read_to_string(&mut buf)?;

    if !buf.ends_with('\n') {
        buf.push('\n');
    }

    key_source.read_to_string(&mut buf)?;

    server_pem.write_all(buf.as_bytes())?;

    Ok(())
}

fn exec_radiusd(debug: bool) -> Result<()> {
    let args = if debug {
        vec![OsString::from("-X")]
    } else {
        vec![
            OsString::from("-f"),
            OsString::from("-l"),
            OsString::from("stdout"),
        ]
    };

    // NOTE: Command.exec() *does not* return if it succeeds. This
    // is why there is no good path - only an error one.
    let err = Command::new(FREERADIUS_EXEC).args(&args).exec();

    Err(anyhow!("failed to exec {FREERADIUS_EXEC}: {err}",))
}

pub fn run(config_override: Option<&Path>, debug: bool) -> Result<()> {
    let config_path = config_override.unwrap_or(CONTAINER_CONFIG_FILE_PATH.as_ref());

    let config = load_radius_config(config_path)?;
    let layout = BootstrapLayout::default();

    let mut clients_conf = fs::File::create(&layout.clients_conf)?;
    write_clients_conf(&config, &mut clients_conf).with_context(|| {
        format!(
            "failed to write clients.conf to {}",
            layout.clients_conf.display()
        )
    })?;

    prepare_certs(&config, &layout)?;

    eprintln!("Configuration set up, starting FreeRADIUS");
    exec_radiusd(debug)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use super::*;
    use rlm_kanidm_shared::config::{KanidmRadiusConfig, RadiusClientConfig};

    #[test]
    fn write_clients_conf_renders_message_authenticator_and_proto() {
        let mut clients_conf = Vec::new();

        let config = KanidmRadiusConfig {
            radius_clients: vec![RadiusClientConfig {
                name: "localhost".to_string(),
                ipaddr: "127.0.0.1".to_string(),
                secret: "radius-secret".to_string(),
            }],
            ..KanidmRadiusConfig::default()
        };

        write_clients_conf(&config, &mut clients_conf).expect("failed to write clients.conf");

        let rendered = String::from_utf8(clients_conf).expect("Invalid utf8 written to vector!");

        assert!(rendered.contains("client localhost {"));
        assert!(rendered.contains("require_message_authenticator = yes"));
        assert!(rendered.contains("proto = *"));
    }

    #[test]
    fn write_server_pem_concatenates_cert_and_key() {
        let mut cert = Cursor::new(b"CERTIFICATE");
        let mut key = Cursor::new(b"PRIVATE KEY");
        let mut server_pem = Vec::new();

        write_server_pem(&mut cert, &mut key, &mut server_pem).expect("failed to write server.pem");

        let pem = String::from_utf8(server_pem).expect("Invalid utf8 written to vector!");
        assert_eq!(pem, "CERTIFICATE\nPRIVATE KEY");
    }
}
