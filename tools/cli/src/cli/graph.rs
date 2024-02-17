use std::collections::HashSet;
use std::future::join;
use kanidm_client::ClientError;
use kanidm_proto::v1::Entry;
use crate::common::OpType;
use crate::{GraphType, handle_client_error, ObjectType, OutputMode, GraphCommonOpt};

impl GraphCommonOpt {

    pub fn debug(&self) -> bool {
        self.copt.debug
    }

    pub async fn exec(&self) {
        let gopt: &GraphCommonOpt = self;
        let copt = &gopt.copt;
        let client = copt.to_client(OpType::Read).await;
        let graph_type = &gopt.graph_type;
        let filters = &gopt.filter;

        let arr_result: [Result<Vec<Entry>, ClientError>; 3] = join!(client.idm_group_list(), client.idm_service_account_list(), client.idm_person_account_list()).await
            .into();
        let list_result: Result<Vec<Entry>, ClientError> = arr_result
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map(|v| { v.into_iter().flatten().collect() });
        let entries = match list_result {
            Ok(entries) => entries,
            Err(e) => {
                handle_client_error(e, copt.output_mode);
                return;
            }
        };

        match copt.output_mode {
            OutputMode::Json => {
                let r_attrs: Vec<_> = entries.iter().map(|entry| &entry.attrs).collect();
                println!(
                    "{}",
                    serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                );
            }
            OutputMode::Text => {
                println!("Showing graph for type: {graph_type:?}, filters: {filters:?}\n");
                let typed_entries = entries.iter()
                    .filter_map(|entry| {
                        let classes = entry.attrs.get("class")?;
                        let uuid = entry.attrs.get("uuid")?.first()?;

                        // Logic to decide the type of each entry
                        let obj_type = if classes.contains(&"group".to_string()) {
                            if uuid.starts_with("00000000-0000-0000-0000-") {
                                ObjectType::BuiltinGroup
                            } else {
                                ObjectType::Group
                            }
                        } else if classes.contains(&"account".to_string()) {
                            if classes.contains(&"person".to_string()) {
                                ObjectType::Person
                            } else {
                                ObjectType::ServiceAccount
                            }
                        } else {
                            return None;
                        };

                        // Filter out the things we want to keep, if the filter is empty we assume we want all.
                        if !filters.contains(&obj_type) && !filters.is_empty() {
                            return None;
                        }

                        let spn = entry.attrs.get("spn")?.first()?;
                        Some((spn.clone(), uuid.clone(), obj_type))
                    }).collect::<HashSet<(String, String, ObjectType)>>();

                // Vec<obj, uuid, obj's members>
                let members_of = entries.into_iter().filter_map(|entry| {
                    let spn = entry.attrs.get("spn")?.first()?.clone();
                    let uuid = entry.attrs.get("uuid")?.first()?.clone();
                    let keep = typed_entries.iter().any(|(_, filtered_uuid, _)| { &uuid == filtered_uuid });
                    if keep {
                        Some((spn, entry.attrs.get("member")?.clone()))
                    } else {
                        None
                    }
                }).collect::<Vec<_>>();

                match graph_type {
                    GraphType::Graphviz => Self::print_graphviz_graph(&typed_entries, &members_of),
                    GraphType::Mermaid => Self::print_mermaid_graph(typed_entries, members_of),
                    GraphType::MermaidElk => {
                        println!(r#"%%{{init: {{"flowchart": {{"defaultRenderer": "elk"}}}} }}%%"#);
                        Self::print_mermaid_graph(typed_entries, members_of);
                    }
                }
            }
        }
    }

    fn print_graphviz_graph(typed_entries: &HashSet<(String, String, ObjectType)>, members_of: &Vec<(String, Vec<String>)>) {
        println!("digraph {{");
        println!(r#"  rankdir="RL""#);

        for (spn, members) in members_of {
            members.iter()
                .filter(|member| typed_entries.iter().any(|(spn, _, _)| spn == *member))
                .for_each(|member| {
                    println!(r#"  "{spn}" -> "{member}""#);
                });
        }

        for (spn, _, obj_type) in typed_entries {
            let (color, shape) = match obj_type {
                ObjectType::Group => ("#b86367", "box"),
                ObjectType::BuiltinGroup => ("#8bc1d6", "component"),
                ObjectType::ServiceAccount => ("#77c98d", "parallelogram"),
                ObjectType::Person => ("#af8bd6", "ellipse"),
            };

            println!(r#"  "{spn}" [color = "{color}", shape = {shape}]"#);
        }
        println!("}}");
    }

    fn print_mermaid_graph(typed_entries: HashSet<(String, String, ObjectType)>, members_of: Vec<(String, Vec<String>)>) {
        println!("graph RL");
        for (spn, members) in members_of {
            members.iter()
                .filter(|member| typed_entries.iter().any(|(spn, _, _)| spn == *member))
                .for_each(|member| {
                    let at_less_name = Self::mermaid_id_from_spn(&spn);
                    let at_less_member = Self::mermaid_id_from_spn(&member);
                    println!("  {at_less_name}[\"{spn}\"] --> {at_less_member}[\"{member}\"]")
                });
        }
        println!("  classDef groupClass fill:#f9f,stroke:#333,stroke-width:4px,stroke-dasharray: 5 5");
        println!("  classDef builtInGroupClass fill:#bbf,stroke:#f66,stroke-width:2px,color:#fff,stroke-dasharray: 5 5");
        println!("  classDef serviceAccountClass fill:#f9f,stroke:#333,stroke-width:4px");
        println!("  classDef personClass fill:#bbf,stroke:#f66,stroke-width:2px,color:#fff");

        for (spn, _, obj_type) in typed_entries {
            let class = match obj_type {
                ObjectType::Group => "groupClass",
                ObjectType::BuiltinGroup => "builtInGroupClass",
                ObjectType::ServiceAccount => "serviceAccountClass",
                ObjectType::Person => "personClass",
            };
            let at_less_name = Self::mermaid_id_from_spn(&spn);
            println!("  {at_less_name}[\"{spn}\"]");
            println!("  class {at_less_name} {class}");
        }
    }

    fn mermaid_id_from_spn(spn: &String) -> String {
        spn.replace('@', "_")
    }
}