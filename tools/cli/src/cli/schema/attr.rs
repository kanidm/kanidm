use crate::{handle_client_error, OpType, SchemaAttrOpt};
use kanidm_proto::scim_v1::{ScimEntryGetQuery, ScimFilter};
use std::str::FromStr;

impl SchemaAttrOpt {
    pub fn debug(&self) -> bool {
        match self {
            Self::List { copt } | Self::Search { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            Self::List { copt } => {
                let client = copt.to_client(OpType::Read).await;

                let attrs = match client.scim_schema_attribute_list(None).await {
                    Ok(attrs) => attrs,
                    Err(e) => {
                        handle_client_error(e, copt.output_mode);
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
            Self::Search { copt, query } => {
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

                let client = copt.to_client(OpType::Read).await;

                let attrs = match client.scim_schema_attribute_list(Some(get_query)).await {
                    Ok(attrs) => attrs,
                    Err(e) => {
                        handle_client_error(e, copt.output_mode);
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
        }
    }
}
