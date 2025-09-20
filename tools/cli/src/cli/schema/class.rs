use crate::{handle_client_error, KanidmClientParser, OpType, SchemaClassOpt};
use kanidm_proto::scim_v1::{ScimEntryGetQuery, ScimFilter};
use std::str::FromStr;

impl SchemaClassOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            Self::List => {
                let client = opt.to_client(OpType::Read).await;

                let classes = match client.scim_schema_class_list(None).await {
                    Ok(classes) => classes,
                    Err(e) => {
                        handle_client_error(e, opt.output_mode);
                        return;
                    }
                };

                for class in classes.resources {
                    println!("{class:?}");
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

                let classes = match client.scim_schema_class_list(Some(get_query)).await {
                    Ok(classes) => classes,
                    Err(e) => {
                        handle_client_error(e, opt.output_mode);
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
