use std::collections::{HashMap, HashSet};
use std::time::Duration;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub fn readable_password_from_random() -> String {
    let mut trng = thread_rng();
    format!(
        "{}-{}-{}-{}",
        (&mut trng)
            .sample_iter(&Alphanumeric)
            .take(4)
            .map(|v| v as char)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&Alphanumeric)
            .take(4)
            .map(|v| v as char)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&Alphanumeric)
            .take(4)
            .map(|v| v as char)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&Alphanumeric)
            .take(4)
            .map(|v| v as char)
            .collect::<String>(),
    )
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub name: String,
    pub display_name: String,
    pub password: String,
    pub uuid: Uuid,
}

impl Account {
    pub fn get_ds_ldap_dn(&self, basedn: &str) -> String {
        format!("uid={},ou=people,{}", self.name.as_str(), basedn)
    }

    pub fn get_ipa_ldap_dn(&self, basedn: &str) -> String {
        format!("uid={},cn=users,cn=accounts,{}", self.name.as_str(), basedn)
    }

    pub fn generate(uuid: Uuid) -> Self {
        let mut rng = rand::thread_rng();
        let id: u64 = rng.gen();
        let name = format!("account_{}", id);
        let display_name = format!("Account {}", id);

        Account {
            name,
            display_name,
            password: readable_password_from_random(),
            uuid,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    pub name: String,
    pub uuid: Uuid,
    pub members: Vec<Uuid>,
}

impl Group {
    pub fn get_ds_ldap_dn(&self, basedn: &str) -> String {
        format!("cn={},ou=groups,{}", self.name.as_str(), basedn)
    }

    pub fn get_ipa_ldap_dn(&self, basedn: &str) -> String {
        format!("cn={},cn=groups,cn=accounts,{}", self.name.as_str(), basedn)
    }

    pub fn generate(uuid: Uuid, members: Vec<Uuid>) -> Self {
        let mut rng = rand::thread_rng();

        let id: u64 = rng.gen();
        let name = format!("group_{}", id);

        Group {
            name,
            uuid,
            members,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Entity {
    Account(Account),
    Group(Group),
}

impl Entity {
    pub fn get_uuid(&self) -> Uuid {
        match self {
            Entity::Account(a) => a.uuid,
            Entity::Group(g) => g.uuid,
        }
    }

    pub fn get_name(&self) -> &str {
        match self {
            Entity::Account(a) => a.name.as_str(),
            Entity::Group(g) => g.name.as_str(),
        }
    }

    pub fn get_ds_ldap_dn(&self, basedn: &str) -> String {
        match self {
            Entity::Account(a) => a.get_ds_ldap_dn(basedn),
            Entity::Group(g) => g.get_ds_ldap_dn(basedn),
        }
    }

    pub fn get_ipa_ldap_dn(&self, basedn: &str) -> String {
        match self {
            Entity::Account(a) => a.get_ipa_ldap_dn(basedn),
            Entity::Group(g) => g.get_ipa_ldap_dn(basedn),
        }
    }

    pub fn get_entity_type(&self) -> EntityType {
        match self {
            Entity::Account(a) => EntityType::Account(a.uuid),
            Entity::Group(g) => EntityType::Group(g.uuid),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntityType {
    Account(Uuid),
    Group(Uuid),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Change {
    Account,
    // What it should be set to
    Group(Vec<Uuid>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OpType {
    Bind(Uuid),
    Add(Vec<Uuid>),
    Mod(Vec<(Uuid, Change)>),
    Delete(Vec<Uuid>),
    Search(Vec<Uuid>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Op {
    pub orig_etime: Duration,
    pub rtime: Duration,
    pub op_type: OpType,
}

impl Op {
    pub fn require_reset<'a>(&'a self) -> Option<Box<dyn Iterator<Item = Uuid> + 'a>> {
        match &self.op_type {
            OpType::Add(ids) => Some(Box::new(ids.iter().copied())),
            OpType::Mod(changes) => Some(Box::new(changes.iter().map(|v| v.0))),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Conn {
    pub id: i32,
    pub ops: Vec<Op>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestData {
    pub all_entities: HashMap<Uuid, Entity>,
    pub access: HashMap<Uuid, Vec<EntityType>>,
    pub accounts: HashSet<Uuid>,
    pub precreate: HashSet<Uuid>,
    pub connections: Vec<Conn>,
}
