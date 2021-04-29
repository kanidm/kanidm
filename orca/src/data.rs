use std::collections::{HashMap, HashSet};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub name: String,
    pub display_name: String,
    pub password: String,
    pub uuid: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    pub name: String,
    pub uuid: Uuid,
    pub members: Vec<Uuid>,
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
    pub accounts: HashSet<Uuid>,
    pub precreate: Vec<Uuid>,
    pub connections: Vec<Conn>,
}
