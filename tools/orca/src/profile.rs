use crate::error::Error;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::path::Path;

// Sorry nerds, capping this at 40 bits.
const ITEM_UPPER_BOUND: u64 = 1 << 40;

const DEFAULT_GROUP_COUNT: u64 = 10;
const DEFAULT_PERSON_COUNT: u64 = 10;

#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    control_uri: String,
    admin_password: String,
    idm_admin_password: String,
    seed: u64,
    extra_uris: Vec<String>,
    // Dimensions of the test to setup.
    group_count: u64,
    person_count: u64,
}

impl Profile {
    pub fn control_uri(&self) -> &str {
        self.control_uri.as_str()
    }

    pub fn extra_uris(&self) -> &[String] {
        self.extra_uris.as_slice()
    }

    pub fn admin_password(&self) -> &str {
        self.admin_password.as_str()
    }

    pub fn idm_admin_password(&self) -> &str {
        self.idm_admin_password.as_str()
    }

    pub fn group_count(&self) -> u64 {
        self.group_count
    }

    pub fn person_count(&self) -> u64 {
        self.person_count
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }
}

pub struct ProfileBuilder {
    pub control_uri: String,
    pub admin_password: String,
    pub idm_admin_password: String,
    pub seed: Option<u64>,
    pub extra_uris: Vec<String>,
    // Dimensions of the test to setup.
    pub group_count: Option<u64>,
    pub person_count: Option<u64>,
}

fn validate_u64_bound(value: Option<u64>, default: u64) -> Result<u64, Error> {
    if let Some(v) = value {
        if v > ITEM_UPPER_BOUND {
            error!("group count exceeds upper bound ({})", ITEM_UPPER_BOUND);
            Err(Error::ProfileBuilder)
        } else {
            Ok(v)
        }
    } else {
        Ok(default)
    }
}

impl ProfileBuilder {
    pub fn new(control_uri: String, admin_password: String, idm_admin_password: String) -> Self {
        ProfileBuilder {
            control_uri,
            admin_password,
            idm_admin_password,
            seed: None,
            extra_uris: Vec::new(),
            group_count: None,
            person_count: None,
        }
    }

    pub fn seed(mut self, seed: Option<u64>) -> Self {
        self.seed = seed;
        self
    }

    pub fn group_count(mut self, group_count: Option<u64>) -> Self {
        self.group_count = group_count;
        self
    }

    pub fn person_count(mut self, person_count: Option<u64>) -> Self {
        self.person_count = person_count;
        self
    }

    pub fn build(self) -> Result<Profile, Error> {
        let ProfileBuilder {
            control_uri,
            admin_password,
            idm_admin_password,
            seed,
            extra_uris,
            group_count,
            person_count,
        } = self;

        let seed: u64 = seed.unwrap_or_else(|| {
            let mut rng = thread_rng();
            rng.gen()
        });

        let extra_uris = Vec::new();

        let group_count = validate_u64_bound(group_count, DEFAULT_GROUP_COUNT)?;
        let person_count = validate_u64_bound(person_count, DEFAULT_PERSON_COUNT)?;

        Ok(Profile {
            control_uri,
            admin_password,
            idm_admin_password,
            seed,
            extra_uris,
            group_count,
            person_count,
        })
    }
}

impl Profile {
    pub fn write_to_path(&self, path: &Path) -> Result<(), Error> {
        let file_contents = toml::to_string(self).map_err(|toml_err| {
            error!(?toml_err);
            Error::SerdeToml
        })?;

        std::fs::write(path, &file_contents).map_err(|io_err| {
            error!(?io_err);
            Error::IoError
        })
    }
}

impl TryFrom<&Path> for Profile {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let file_contents = std::fs::read_to_string(path).map_err(|io_err| {
            error!(?io_err);
            Error::IoError
        })?;

        toml::from_str(&file_contents).map_err(|toml_err| {
            error!(?toml_err);
            Error::SerdeToml
        })
    }
}
