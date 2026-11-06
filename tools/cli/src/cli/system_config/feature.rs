use crate::OpType;

use crate::{FeatureOpt, KanidmClientParser, OutputMode};
// use kanidm_proto::scim_v1::{ScimEntryGetQuery};

impl FeatureOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            Self::List => {
                let client = opt.to_client(OpType::Read).await;
                let query = None;

                match client.idm_feature_list(query).await {
                    Ok(list) => match opt.output_mode {
                        OutputMode::Json => {
                            let json = serde_json::to_string(&list)
                                .expect("Failed to serialise list to JSON!");
                            println!("{json}");
                        }
                        OutputMode::Text => {
                            // Print each entry on a new line
                            list.resources.iter().for_each(|entry| {
                                println!("feature_id:   {}", entry.header.id);
                                println!("name:         {}", entry.name);
                                println!("desc:         {}", entry.description);
                                println!("enabled:      {}", entry.enabled);

                                println!();
                            });
                            eprintln!("--");
                            eprintln!("Success");
                        }
                    },
                    Err(e) => crate::handle_client_error(e, opt.output_mode),
                }
            }

            Self::Enable { feature_name } => {
                let client = opt.to_client(OpType::Write).await;

                if let Err(e) = client.idm_feature_enable(feature_name).await {
                    crate::handle_client_error(e, opt.output_mode);
                } else {
                    opt.output_mode.print_message("Feature Enabled");
                }
            }

            Self::Disable { feature_name } => {
                let client = opt.to_client(OpType::Write).await;

                if let Err(e) = client.idm_feature_disable(feature_name).await {
                    crate::handle_client_error(e, opt.output_mode);
                } else {
                    opt.output_mode.print_message("Feature Disabled");
                }
            }
        }
    }
}
