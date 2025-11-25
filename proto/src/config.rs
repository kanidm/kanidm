use serde::Deserialize;
use std::{fmt, fmt::Display, str::FromStr};

#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
pub enum ServerRole {
    #[default]
    WriteReplica,
    WriteReplicaNoUI,
    ReadOnlyReplica,
}

impl Display for ServerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerRole::WriteReplica => f.write_str("write replica"),
            ServerRole::WriteReplicaNoUI => f.write_str("write replica (no ui)"),
            ServerRole::ReadOnlyReplica => f.write_str("read only replica"),
        }
    }
}

impl FromStr for ServerRole {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "write_replica" => Ok(ServerRole::WriteReplica),
            "write_replica_no_ui" => Ok(ServerRole::WriteReplicaNoUI),
            "read_only_replica" => Ok(ServerRole::ReadOnlyReplica),
            _ => Err("Must be one of write_replica, write_replica_no_ui, read_only_replica"),
        }
    }
}
