use serde::{Deserialize, Serialize};
use serde_with::formats::CommaSeparator;
use serde_with::{serde_as, DefaultOnNull, StringWithSeparator};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct EtcDb {
    pub users: Vec<EtcUser>,
    pub shadow: Vec<EtcShadow>,
    pub groups: Vec<EtcGroup>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
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

pub fn read_etc_passwd_file<P: AsRef<Path>>(path: P) -> Result<Vec<EtcUser>, UnixIntegrationError> {
    let mut file = File::open(path.as_ref()).map_err(|_| UnixIntegrationError)?;

    let mut contents = vec![];
    file.read_to_end(&mut contents)
        .map_err(|_| UnixIntegrationError)?;

    parse_etc_passwd(contents.as_slice()).map_err(|_| UnixIntegrationError)
}

#[derive(PartialEq, Default, Clone)]
pub enum CryptPw {
    Sha256(String),
    Sha512(String),
    #[default]
    Invalid,
}

impl fmt::Display for CryptPw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptPw::Invalid => write!(f, "x"),
            CryptPw::Sha256(s) | CryptPw::Sha512(s) => write!(f, "{}", s),
        }
    }
}

impl fmt::Debug for CryptPw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptPw::Invalid => write!(f, "x"),
            CryptPw::Sha256(_s) => write!(f, "crypt sha256"),
            CryptPw::Sha512(_s) => write!(f, "crypt sha512"),
        }
    }
}

impl FromStr for CryptPw {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.starts_with("$6$") {
            Ok(CryptPw::Sha512(value.to_string()))
        } else if value.starts_with("$5$") {
            Ok(CryptPw::Sha256(value.to_string()))
        } else {
            Ok(CryptPw::Invalid)
        }
    }
}

impl CryptPw {
    pub fn is_valid(&self) -> bool {
        !matches!(self, CryptPw::Invalid)
    }

    pub fn check_pw(&self, cred: &str) -> bool {
        match &self {
            CryptPw::Sha256(crypt) => sha_crypt::sha256_check(cred, crypt.as_str()).is_ok(),
            CryptPw::Sha512(crypt) => sha_crypt::sha512_check(cred, crypt.as_str()).is_ok(),
            CryptPw::Invalid => false,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct EtcShadow {
    pub name: String,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub password: CryptPw,
    // 0 means must change next login.
    // None means all other aging features are disabled
    pub epoch_change_days: Option<i64>,
    // 0 means no age
    #[serde_as(deserialize_as = "DefaultOnNull")]
    pub days_min_password_age: i64,
    pub days_max_password_age: Option<i64>,
    // 0 means no warning
    #[serde_as(deserialize_as = "DefaultOnNull")]
    pub days_warning_period: i64,
    // Number of days after max_password_age passes where the password can
    // still be accepted such that the user can update their password
    pub days_inactivity_period: Option<i64>,
    pub epoch_expire_date: Option<i64>,
    pub flag_reserved: Option<u32>,
}

pub fn parse_etc_shadow(bytes: &[u8]) -> Result<Vec<EtcShadow>, UnixIntegrationError> {
    use csv::ReaderBuilder;
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b':')
        .from_reader(bytes);
    rdr.deserialize()
        .map(|result| {
            result.map_err(|err| {
                eprintln!("{:?}", err);
                UnixIntegrationError
            })
        })
        .collect::<Result<Vec<EtcShadow>, UnixIntegrationError>>()
}

pub fn read_etc_shadow_file<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<EtcShadow>, UnixIntegrationError> {
    let mut file = File::open(path.as_ref()).map_err(|_| UnixIntegrationError)?;

    let mut contents = vec![];
    file.read_to_end(&mut contents)
        .map_err(|_| UnixIntegrationError)?;

    parse_etc_shadow(contents.as_slice()).map_err(|_| UnixIntegrationError)
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EtcGroup {
    pub name: String,
    pub password: String,
    pub gid: u32,
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
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

pub fn read_etc_group_file<P: AsRef<Path>>(path: P) -> Result<Vec<EtcGroup>, UnixIntegrationError> {
    let mut file = File::open(path.as_ref()).map_err(|_| UnixIntegrationError)?;

    let mut contents = vec![];
    file.read_to_end(&mut contents)
        .map_err(|_| UnixIntegrationError)?;

    parse_etc_group(contents.as_slice()).map_err(|_| UnixIntegrationError)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_PASSWD: &str = r#"root:x:0:0:root:/root:/bin/bash
systemd-timesync:x:498:498:systemd Time Synchronization:/:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/var/lib/nobody:/bin/bash
"#;

    #[test]
    fn test_parse_passwd() {
        let users =
            parse_etc_passwd(EXAMPLE_PASSWD.as_bytes()).expect("Failed to parse passwd data");

        assert_eq!(
            users[0],
            EtcUser {
                name: "root".to_string(),
                password: "x".to_string(),
                uid: 0,
                gid: 0,
                gecos: "root".to_string(),
                homedir: "/root".to_string(),
                shell: "/bin/bash".to_string(),
            }
        );

        assert_eq!(
            users[1],
            EtcUser {
                name: "systemd-timesync".to_string(),
                password: "x".to_string(),
                uid: 498,
                gid: 498,
                gecos: "systemd Time Synchronization".to_string(),
                homedir: "/".to_string(),
                shell: "/usr/sbin/nologin".to_string(),
            }
        );

        assert_eq!(
            users[2],
            EtcUser {
                name: "nobody".to_string(),
                password: "x".to_string(),
                uid: 65534,
                gid: 65534,
                gecos: "nobody".to_string(),
                homedir: "/var/lib/nobody".to_string(),
                shell: "/bin/bash".to_string(),
            }
        );
    }

    // IMPORTANT this is the password "a". Very secure, totes secret.
    const EXAMPLE_SHADOW: &str = r#"sshd:!:19978::::::
tss:!:19980::::::
admin:$6$5.bXZTIXuVv.xI3.$sAubscCJPwnBWwaLt2JR33lo539UyiDku.aH5WVSX0Tct9nGL2ePMEmrqT3POEdBlgNQ12HJBwskewGu2dpF//:19980:0:99999:7:::
"#;

    #[test]
    fn test_parse_shadow() {
        let shadow =
            parse_etc_shadow(EXAMPLE_SHADOW.as_bytes()).expect("Failed to parse passwd data");

        assert_eq!(
            shadow[0],
            EtcShadow {
                name: "sshd".to_string(),
                password: CryptPw::Invalid,
                epoch_change_days: Some(19978),
                days_min_password_age: 0,
                days_max_password_age: None,
                days_warning_period: 0,
                days_inactivity_period: None,
                epoch_expire_date: None,
                flag_reserved: None
            }
        );

        assert_eq!(
            shadow[1],
            EtcShadow {
                name: "tss".to_string(),
                password: CryptPw::Invalid,
                epoch_change_days: Some(19980),
                days_min_password_age: 0,
                days_max_password_age: None,
                days_warning_period: 0,
                days_inactivity_period: None,
                epoch_expire_date: None,
                flag_reserved: None
            }
        );

        assert_eq!(shadow[2], EtcShadow {
            name: "admin".to_string(),
            password: CryptPw::Sha512("$6$5.bXZTIXuVv.xI3.$sAubscCJPwnBWwaLt2JR33lo539UyiDku.aH5WVSX0Tct9nGL2ePMEmrqT3POEdBlgNQ12HJBwskewGu2dpF//".to_string()),
            epoch_change_days: Some(19980),
            days_min_password_age: 0,
            days_max_password_age: Some(99999),
            days_warning_period: 7,
            days_inactivity_period: None,
            epoch_expire_date: None,
            flag_reserved: None
        });
    }

    const EXAMPLE_GROUP: &str = r#"root:x:0:
wheel:x:481:admin,testuser
"#;

    #[test]
    fn test_parse_group() {
        let groups = parse_etc_group(EXAMPLE_GROUP.as_bytes()).expect("Failed to parse groups");

        assert_eq!(
            groups[0],
            EtcGroup {
                name: "root".to_string(),
                password: "x".to_string(),
                gid: 0,
                members: vec![]
            }
        );

        assert_eq!(
            groups[1],
            EtcGroup {
                name: "wheel".to_string(),
                password: "x".to_string(),
                gid: 481,
                members: vec!["admin".to_string(), "testuser".to_string(),]
            }
        );
    }
}
