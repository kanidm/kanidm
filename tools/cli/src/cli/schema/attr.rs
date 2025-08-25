use crate::{handle_client_error, KanidmClientParser, OpType, OutputMode, SchemaAttrOpt};
use kanidm_proto::scim_v1::{ScimEntryGetQuery, ScimFilter};
use std::str::FromStr;

impl SchemaAttrOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            Self::List => {
                let client = opt.to_client(OpType::Read).await;

                let attrs = match client.scim_schema_attribute_list(None).await {
                    Ok(attrs) => attrs,
                    Err(e) => {
                        handle_client_error(e, opt.output_mode);
                        return;
                    }
                };

                for attr in attrs.resources {
                    println!("---");
                    println!("uuid: {}", attr.header.id);
                    println!("attribute_name: {}", attr.attributename);
                    println!("description: {}", attr.description);
                    println!("multivalue: {}", attr.multivalue);
                    println!("unique: {}", attr.unique);
                    println!("syntax: {}", attr.syntax);
                }
            }
            Self::Search { query } => {
                let query = match ScimFilter::from_str(query) {
                    Ok(query) => query,
                    Err(err) => {
                        error!("Invalid search query");
                        error!(?err);
                        return;
                    }
                };

                let get_query = ScimEntryGetQuery {
                    filter: Some(query),
                    ..Default::default()
                };

                let client = opt.to_client(OpType::Read).await;

                let attrs = match client.scim_schema_attribute_list(Some(get_query)).await {
                    Ok(attrs) => attrs,
                    Err(e) => {
                        handle_client_error(e, opt.output_mode);
                        return;
                    }
                };
                match opt.output_mode {
                    OutputMode::Json => {
                        println!(
                            "{}",
                            serde_json::to_string(&attrs.resources)
                                .expect("Failed to serialise attributes to JSON")
                        );
                    }
                    OutputMode::Text => {
                        let total = attrs.resources.len();
                        for (index, attr) in attrs.resources.iter().enumerate() {
                            println!("uuid: {}", attr.header.id);
                            println!("attribute_name: {}", attr.attributename);
                            println!("description: {}", attr.description);
                            println!("multivalue: {}", attr.multivalue);
                            println!("unique: {}", attr.unique);
                            println!("syntax: {}", attr.syntax);
                            if index < total - 1 {
                                println!("---");
                            }
                        }
                    }
                }
            }
        }
    }
}
