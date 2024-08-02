use crate::error::Error;
use crate::model::{ActorModel, ActorRole};
use crate::models;
use crate::profile::Profile;
use core::fmt::Display;
use kanidm_client::KanidmClient;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;
/// A serialisable state representing the content of a kanidm database and potential
/// test content that can be created and modified.
///
/// This is all generated ahead of time before the test so that during the test
/// as minimal calculation as possible is required.
#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub profile: Profile,
    // ----------------------------
    pub preflight_flags: Vec<Flag>,
    pub persons: Vec<Person>,
    pub groups: Vec<Group>,
    pub thread_count: Option<usize>, // oauth_clients: Vec<Oauth2Clients>,
}

impl State {
    pub fn write_to_path(&self, path: &Path) -> Result<(), Error> {
        let output = std::fs::File::create(path).map_err(|io_err| {
            error!(?io_err);
            Error::Io
        })?;

        serde_json::to_writer(output, self).map_err(|json_err| {
            error!(?json_err);
            Error::SerdeJson
        })
    }
}

impl TryFrom<&Path> for State {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let input = std::fs::File::open(path).map_err(|io_err| {
            error!(?io_err);
            Error::Io
        })?;

        serde_json::from_reader(input).map_err(|json_err| {
            error!(?json_err);
            Error::SerdeJson
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Flag {
    DisableAllPersonsMFAPolicy,
    ExtendPrivilegedAuthExpiry,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub enum PreflightState {
    #[default]
    Present,
    Absent,
}

/// A model defines *how* an actors makes it's choices. For example the choices
/// could be purely random, they could be a linear pattern, or they could have
/// some set of weights related to choices they make.
///
/// Some models can *restrict* the set of choices that an actor may make.
///
/// This compliments ActorRoles, which define the extended actions an Actor may
/// choose to perform. If ActorRoles are present, the model MAY choose to use
/// these roles to perform extended operations.
#[derive(clap::ValueEnum, Debug, Serialize, Deserialize, Clone, Default, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Model {
    /// This is a "hardcoded" model that just authenticates and searches
    AuthOnly,
    /// A simple linear executor that does actions in a loop.
    #[default]
    Basic,
    /// This model only performs read requests in a loop
    Reader,
    /// This model only performs write requests in a loop
    Writer,
    /// This model adds empty group to a sever and measures how long it takes before they are replicated to the other servers
    LatencyMeasurer,
}

impl Model {
    pub fn as_dyn_object(
        self,
        rng_seed: u64,
        additional_clients: Vec<KanidmClient>,
        person_name: &str,
        warmup_time: Duration,
    ) -> Result<Box<dyn ActorModel + Send + '_>, Error> {
        let cha_rng = ChaCha8Rng::seed_from_u64(rng_seed);
        let warmup_time_as_ms = warmup_time.as_millis() as u64;
        Ok(match self {
            Model::AuthOnly => Box::new(models::auth_only::ActorAuthOnly::new()),
            Model::Basic => Box::new(models::basic::ActorBasic::new(cha_rng, warmup_time_as_ms)),
            Model::Reader => Box::new(models::read::ActorReader::new(cha_rng, warmup_time_as_ms)),
            Model::Writer => Box::new(models::write::ActorWriter::new(cha_rng, warmup_time_as_ms)),
            Model::LatencyMeasurer => {
                Box::new(models::latency_measurer::ActorLatencyMeasurer::new(
                    cha_rng,
                    additional_clients,
                    person_name,
                    warmup_time_as_ms,
                )?)
            }
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Credential {
    Password { plain: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Person {
    pub preflight_state: PreflightState,
    pub username: String,
    pub display_name: String,
    pub roles: BTreeSet<ActorRole>,
    pub credential: Credential,
    pub model: Model,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Group {
    pub name: GroupName,
    pub preflight_state: PreflightState,
    pub role: ActorRole,
    pub members: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Default, Ord, Eq, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum GroupName {
    RolePeopleSelfSetPassword,
    #[default]
    RolePeoplePiiReader,
    RolePeopleSelfMailWrite,
    RolePeopleSelfReadProfile,
    RolePeopleSelfReadMemberOf,
    RolePeopleGroupAdmin,
}

impl Display for GroupName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            toml::to_string(self)
                .expect("Failed to parse group name as string")
                .trim_matches('"')
        )
    }
}

impl TryFrom<&String> for GroupName {
    type Error = toml::de::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        toml::from_str(&format!("\"{value}\""))
    }
}

#[cfg(test)]
mod test {

    use super::GroupName;

    #[test]
    fn test_group_names_parsing() {
        let group_names = vec![
            GroupName::RolePeopleGroupAdmin,
            GroupName::RolePeoplePiiReader,
            GroupName::RolePeopleSelfReadMemberOf,
        ];
        for name in group_names {
            let str = name.to_string();
            let parsed_group_name = GroupName::try_from(&str).expect("Failed to parse group name");

            assert_eq!(parsed_group_name, name);
            dbg!(str);
        }
    }

    #[test]
    fn test_group_name_from_str() {
        let group_admin = "role_people_group_admin";
        assert_eq!(
            GroupName::RolePeopleGroupAdmin,
            GroupName::try_from(&group_admin.to_string()).unwrap()
        )
    }
}
