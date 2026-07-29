use crate::{handle_client_error, ApplicationOpt, KanidmClientParser, OpType};

use kanidm_proto::scim_v1::client::{ScimEntryApplicationPost, ScimReference};

impl ApplicationOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            Self::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_application_list(None).await {
                    Ok(response) => opt.output_mode.print_struct(&response),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            Self::Create {
                name,
                displayname,
                linked_group,
            } => {
                let client = opt.to_client(OpType::Write).await;

                let linked_group = ScimReference::from(linked_group);

                let application = ScimEntryApplicationPost {
                    name: name.clone(),
                    displayname: displayname.clone(),
                    linked_group,
                };

                match client.idm_application_create(&application).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            Self::Get { name } => {
                let client = opt.to_client(OpType::Read).await;

                match client.idm_application_get(name, None).await {
                    Ok(response) => opt.output_mode.print_struct(&response),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            Self::Delete { name } => {
                let client = opt.to_client(OpType::Write).await;

                match client.idm_application_delete(name).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}
