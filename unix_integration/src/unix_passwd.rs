use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};

use std::fmt;

#[derive(Serialize, Deserialize, Debug)]
pub struct EtcUser {
    pub name: String,
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub homedir: String,
    pub shell: String,
}

pub fn parse_etc_passwd(bytes: &[u8]) -> Result<Vec<EtcUser>, UnixIntegrationError> {
    use csv::ReaderBuilder;
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b':')
        .from_reader(bytes);
    rdr.deserialize()
        .map(|result| result.map_err(|_e| UnixIntegrationError))
        .collect::<Result<Vec<EtcUser>, UnixIntegrationError>>()
}

fn members<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct InnerCsv;

    impl<'de> Visitor<'de> for InnerCsv {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(value.split(',').map(|s| s.to_string()).collect())
        }
    }

    deserializer.deserialize_str(InnerCsv)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EtcGroup {
    pub name: String,
    pub password: String,
    pub gid: u32,
    #[serde(deserialize_with = "members")]
    pub members: Vec<String>,
}

#[derive(Debug)]
pub struct UnixIntegrationError;

pub fn parse_etc_group(bytes: &[u8]) -> Result<Vec<EtcGroup>, UnixIntegrationError> {
    use csv::ReaderBuilder;
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b':')
        .from_reader(bytes);
    rdr.deserialize()
        .map(|result| result.map_err(|_e| UnixIntegrationError))
        .collect::<Result<Vec<EtcGroup>, UnixIntegrationError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_PASSWD: &str = r#"root:x:0:0:root:/root:/bin/bash
systemd-timesync:x:498:498:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:484:484:User for D-Bus:/run/dbus:/usr/sbin/nologin
tftp:x:483:483:TFTP Account:/srv/tftpboot:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/var/lib/nobody:/bin/bash
"#;

    const EXAMPLE_GROUP: &str = r#"root:x:0:
shadow:x:15:
trusted:x:42:
users:x:100:
systemd-journal:x:499:
systemd-timesync:x:498:
kmem:x:497:
lock:x:496:
tty:x:5:
wheel:x:481:admin,testuser
"#;

    #[test]
    fn test_parse_passwd() {
        for record in parse_etc_passwd(EXAMPLE_PASSWD.as_bytes()).unwrap() {
            println!("{:?}", record);
        }
    }

    #[test]
    fn test_parse_group() {
        for record in parse_etc_group(EXAMPLE_GROUP.as_bytes()).unwrap() {
            println!("{:?}", record);
        }
    }
}
