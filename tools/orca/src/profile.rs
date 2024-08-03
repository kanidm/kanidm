use crate::error::Error;
use crate::state::{GroupName, Model};
use rand::{thread_rng, Rng};
use serde::de::{value, IntoDeserializer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

// Sorry nerds, capping this at 40 bits.
const ITEM_UPPER_BOUND: u64 = 1 << 40;

const DEFAULT_GROUP_COUNT: u64 = 10;
const DEFAULT_PERSON_COUNT: u64 = 10;

const DEFAULT_WARMUP_TIME: u64 = 10;
const DEFAULT_TEST_TIME: Option<u64> = Some(180);

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupProperties {
    pub member_count: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    control_uri: String,
    admin_password: String,
    idm_admin_password: String,
    seed: i64,
    extra_uris: Vec<String>,
    // Dimensions of the test to setup.
    warmup_time: u64,
    test_time: Option<u64>,
    group_count: u64,
    person_count: u64,
    thread_count: Option<usize>,
    model: Model,
    group: BTreeMap<String, GroupProperties>,
    #[serde(default)]
    dump_raw_data: bool,
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

    #[allow(dead_code)]
    pub fn group_count(&self) -> u64 {
        self.group_count
    }

    pub fn person_count(&self) -> u64 {
        self.person_count
    }

    pub fn thread_count(&self) -> Option<usize> {
        self.thread_count
    }

    pub fn get_properties_by_group(&self) -> &BTreeMap<String, GroupProperties> {
        &self.group
    }

    pub fn seed(&self) -> u64 {
        if self.seed < 0 {
            self.seed.wrapping_mul(-1) as u64
        } else {
            self.seed as u64
        }
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    pub fn warmup_time(&self) -> Duration {
        Duration::from_secs(self.warmup_time)
    }

    pub fn test_time(&self) -> Option<Duration> {
        self.test_time.map(Duration::from_secs)
    }

    pub fn dump_raw_data(&self) -> bool {
        self.dump_raw_data
    }
}

pub struct ProfileBuilder {
    pub control_uri: String,
    pub admin_password: String,
    pub idm_admin_password: String,
    pub seed: Option<u64>,
    pub extra_uris: Vec<String>,
    // Dimensions of the test to setup.
    pub warmup_time: Option<u64>,
    pub test_time: Option<Option<u64>>,
    pub group_count: Option<u64>,
    pub person_count: Option<u64>,
    pub thread_count: Option<usize>,
    pub model: Model,
    pub dump_raw_data: bool,
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
    pub fn new(
        control_uri: String,
        extra_uris: Vec<String>,
        admin_password: String,
        idm_admin_password: String,
        model: Model,
        thread_count: Option<usize>,
        dump_raw_data: bool,
    ) -> Self {
        ProfileBuilder {
            control_uri,
            extra_uris,
            admin_password,
            idm_admin_password,
            seed: None,
            warmup_time: None,
            test_time: None,
            group_count: None,
            person_count: None,
            thread_count,
            model,
            dump_raw_data,
        }
    }

    pub fn seed(mut self, seed: Option<u64>) -> Self {
        self.seed = seed;
        self
    }

    #[allow(dead_code)]
    pub fn warmup_time(mut self, time: Option<u64>) -> Self {
        self.warmup_time = time;
        self
    }

    #[allow(dead_code)]
    pub fn test_time(mut self, time: Option<Option<u64>>) -> Self {
        self.test_time = time;
        self
    }

    #[allow(dead_code)]
    pub fn group_count(mut self, group_count: Option<u64>) -> Self {
        self.group_count = group_count;
        self
    }

    #[allow(dead_code)]
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
            warmup_time,
            test_time,
            group_count,
            person_count,
            thread_count,
            model,
            dump_raw_data,
        } = self;

        let seed: u64 = seed.unwrap_or_else(|| {
            let mut rng = thread_rng();
            rng.gen()
        });

        //TODO: Allow to specify group properties from the CLI
        let group = BTreeMap::new();

        let group_count = validate_u64_bound(group_count, DEFAULT_GROUP_COUNT)?;
        let person_count = validate_u64_bound(person_count, DEFAULT_PERSON_COUNT)?;

        let warmup_time = warmup_time.unwrap_or(DEFAULT_WARMUP_TIME);
        let test_time = test_time.unwrap_or(DEFAULT_TEST_TIME);

        let seed: i64 = if seed > i64::MAX as u64 {
            // let it wrap around
            let seed = seed - i64::MAX as u64;
            -(seed as i64)
        } else {
            seed as i64
        };

        Ok(Profile {
            control_uri,
            admin_password,
            idm_admin_password,
            seed,
            extra_uris,
            warmup_time,
            test_time,
            group_count,
            person_count,
            thread_count,
            group,
            model,
            dump_raw_data,
        })
    }
}

impl Profile {
    pub fn write_to_path(&self, path: &Path) -> Result<(), Error> {
        let file_contents = toml::to_string(self).map_err(|toml_err| {
            error!(?toml_err);
            Error::SerdeToml
        })?;

        std::fs::write(path, file_contents).map_err(|io_err| {
            error!(?io_err);
            Error::Io
        })
    }

    fn validate_group_names_and_member_count(&self) -> Result<(), Error> {
        for (group_name, group_properties) in self.group.iter() {
            let _ = GroupName::deserialize(group_name.as_str().into_deserializer()).map_err(
                |_: value::Error| {
                    error!("Invalid group name provided: {group_name}");
                    Error::InvalidState
                },
            )?;
            let provided_member_count = group_properties.member_count.unwrap_or_default();
            let max_member_count = self.person_count();
            if provided_member_count > max_member_count {
                error!("Member count of {group_name} is out of bound: max value is {max_member_count}, but {provided_member_count} was provided");
                return Err(Error::InvalidState);
            }
        }
        Ok(())
    }
}

impl TryFrom<&Path> for Profile {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let file_contents = std::fs::read_to_string(path).map_err(|io_err| {
            error!(?io_err);
            Error::Io
        })?;

        let profile: Profile = toml::from_str(&file_contents).map_err(|toml_err| {
            error!(?toml_err);
            Error::SerdeToml
        })?;
        profile.validate_group_names_and_member_count()?;

        Ok(profile)
    }
}
