//! I'm working towards making this a proper enumeration/discovery toolkit for access things in Kanidm.
//!
//! - @yaleman
//!

use std::collections::{BTreeMap, BTreeSet};
// use kanidm_client::KanidmClient;
use kanidmd_lib::constants::entries::Attribute;
use kanidmd_lib::constants::groups::{idm_builtin_admin_groups, idm_builtin_non_admin_groups};
use kanidmd_lib::prelude::{builtin_accounts, EntryInitNew};
use petgraph::graphmap::{AllEdges, GraphMap, NodeTrait};
use petgraph::Directed;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
enum EdgeType {
    MemberOf,
}
#[derive(Debug)]
enum EntryType {
    Person(String),
    ServiceAccount(String),
    Group(String),
    UnknownType(String),
}

impl EntryType {
    fn as_mermaid_tag(&self) -> String {
        match self {
            EntryType::Person(name) => format!("{}(\"Person:{}\")", name, name),
            EntryType::ServiceAccount(name) => format!("{}{{\"SA: {}\"}}", name, name),
            EntryType::Group(name) => format!("{}[\"Group: {}\"]", name, name),
            EntryType::UnknownType(name) => format!("{}[\"Unknown Type {}\"]", name, name),
        }
    }
}

impl From<&EntryInitNew> for EntryType {
    fn from(entry: &EntryInitNew) -> Self {
        let name = entry.get_ava_single(Attribute::Name).unwrap();
        let name = name.as_string().unwrap();
        let classes = entry
            .get_ava_set(Attribute::Class)
            .unwrap()
            .as_iutf8_set()
            .cloned()
            .unwrap_or(BTreeSet::<String>::new());
        if classes.contains("group") {
            EntryType::Group(name.clone())
        } else if classes.contains("service_account") {
            EntryType::ServiceAccount(name.clone())
        } else if classes.contains("person") {
            EntryType::Person(name.clone())
        } else {
            EntryType::UnknownType(name.clone())
        }
    }
}

struct Graph<T>(GraphMap<T, EdgeType, petgraph::Directed>);

impl<T> Graph<T>
where
    T: core::hash::Hash + Ord + NodeTrait,
{
    fn new() -> Self {
        Graph(GraphMap::<T, EdgeType, petgraph::Directed>::new())
    }

    fn add_node(&mut self, n: T) {
        self.0.add_node(n);
    }
    fn add_edge(&mut self, l: T, r: T, t: EdgeType) {
        self.0.add_edge(l, r, t);
    }
    fn all_edges(&mut self) -> AllEdges<'_, T, EdgeType, Directed> {
        self.0.all_edges()
    }

    /// The uuidmap is a map of uuids to EntryInitNew objects, which we use to get the name of the objects
    fn as_mermaid(&mut self, uuidmap: &BTreeMap<T, EntryInitNew>) -> String {
        let mut res = format!("graph RL;\n");
        for (left, right, _weight) in self.all_edges() {
            let left = uuidmap.get(&left).unwrap();
            let right = uuidmap.get(&right).unwrap();

            res = format!(
                "{}  {} --> {}\n",
                res,
                EntryType::from(left).as_mermaid_tag(),
                EntryType::from(right).as_mermaid_tag(),
            );
        }
        res
    }
}

async fn enumerate_default_groups(/*_client: KanidmClient*/) {
    let mut uuidmap: BTreeMap<Uuid, EntryInitNew> = BTreeMap::new();

    let mut graph = Graph::new();

    builtin_accounts().into_iter().for_each(|account| {
        // println!("adding builtin {}", account.uuid);
        uuidmap.insert(account.uuid, account.clone().try_into().unwrap());
        graph.add_node(account.uuid);
    });

    let mut groups = idm_builtin_admin_groups();
    groups.extend(idm_builtin_non_admin_groups());

    groups.into_iter().for_each(|group| {
        uuidmap.insert(group.uuid, group.clone().try_into().unwrap());
        graph.add_node(group.uuid);

        // handle the membership
        group.members.iter().for_each(|member| {
            graph.add_edge(*member, group.uuid, EdgeType::MemberOf);
        });
    });

    println!("{}", graph.as_mermaid(&uuidmap))
}

#[tokio::main]
async fn main() {
    enumerate_default_groups().await;
}
