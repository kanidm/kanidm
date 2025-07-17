use crate::{handle_client_error, OpType, SchemaClassOpt};
use kanidm_proto::scim_v1::{ScimEntryGetQuery, ScimFilter};
use std::str::FromStr;

impl SchemaClassOpt {
    pub fn debug(&self) -> bool {
        match self {
            Self::List { copt } | Self::Search { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            Self::List { copt } => {
                let client = copt.to_client(OpType::Read).await;

                let classes = match client.scim_schema_class_list(None).await {
                    Ok(classes) => classes,
                    Err(e) => {
                        handle_client_error(e, copt.output_mode);
                        return;
                    }
                };

                for class in classes.resources {
                    println!("{class:?}");
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

                let classes = match client.scim_schema_class_list(Some(get_query)).await {
                    Ok(classes) => classes,
                    Err(e) => {
                        handle_client_error(e, copt.output_mode);
                        return;
                    }
                };

                for class in classes.resources {
                    println!("{class:?}");
                }
            }
        }
    }
}
