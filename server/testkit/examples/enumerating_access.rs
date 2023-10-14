// #[cfg(target_feature = "enumeration")]

use std::collections::{BTreeSet, HashMap};
// use kanidm_client::KanidmClient;
use kanidmd_lib::constants::entries::Attribute;
use kanidmd_lib::constants::groups::{idm_builtin_admin_groups, idm_builtin_non_admin_groups};
use kanidmd_lib::prelude::{builtin_accounts, EntryInitNew};
use petgraph::graphmap::GraphMap;
use uuid::Uuid;

async fn enumerate_default_groups(/*_client: KanidmClient*/) {
    let mut uuidmap: HashMap<Uuid, EntryInitNew> = HashMap::new();

    let mut graph = GraphMap::<Uuid, (), petgraph::Undirected>::new();

    builtin_accounts().into_iter().for_each(|account| {
        // println!("adding builtin {}", account.uuid);
        uuidmap.insert(account.uuid, account.clone().try_into().unwrap());
        graph.add_node(account.uuid);
    });

    idm_builtin_non_admin_groups()
        .into_iter()
        .for_each(|group| {
            uuidmap.insert(group.uuid, group.clone().try_into().unwrap());
            graph.add_node(group.uuid);

            group.members.iter().for_each(|member| {
                graph.add_edge(*member, group.uuid, ());
            });
        });

    idm_builtin_admin_groups().into_iter().for_each(|group| {
        uuidmap.insert(group.uuid, group.clone().try_into().unwrap());
        graph.add_node(group.uuid);

        group.members.iter().for_each(|member| {
            graph.add_edge(*member, group.uuid, ());
        });
    });

    // // println!("{}", mermaidchart);
    // let mut dotgraph = format!("{:?}", Dot::with_config(&graph, &[Config::EdgeNoLabel]));
    // // regex to extract uuids
    // // let re = regex::Regex::new(r"(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})").unwrap();
    // for (uuid, uuid_value) in uuidmap.clone() {
    //     let uuid_str = uuid.to_string();
    //     if dotgraph.contains(&uuid_str) {
    //         // println!("uuid {} not found in graph", uuid_str);
    //         let name = uuid_value.get_ava_single(Attribute::Name).unwrap();
    //         dotgraph = dotgraph.replace(&uuid_str, name.as_string().unwrap());
    //     }
    // }
    // // println!("{}", dotgraph);

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

    impl From<EntryInitNew> for EntryType {
        fn from(entry: EntryInitNew) -> Self {
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

    println!("graph RL;");
    for (left, right, _weight) in graph.all_edges() {
        let left = uuidmap.get(&left).unwrap();
        // let left_name = left.get_ava_single(Attribute::Name).unwrap();

        let right = uuidmap.get(&right).unwrap();
        // let right_name = right.get_ava_single(Attribute::Name).unwrap();

        println!(
            "  {} --> {}",
            EntryType::from(left.clone()).as_mermaid_tag(),
            EntryType::from(right.clone()).as_mermaid_tag(),
        );
    }
}

#[tokio::main]
async fn main() {
    enumerate_default_groups().await;
}
