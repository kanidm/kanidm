use crate::OpType;

use crate::{handle_client_error, DeniedNamesOpt, KanidmClientParser, OutputMode};

impl DeniedNamesOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            DeniedNamesOpt::Show => {
                let client = opt.to_client(OpType::Read).await;
                match client.system_denied_names_get().await {
                    Ok(list) => match opt.output_mode {
                        OutputMode::Json => {
                            let json = serde_json::to_string(&list)
                                .expect("Failed to serialise list to JSON!");
                            println!("{json}");
                        }
                        OutputMode::Text => {
                            for i in list {
                                println!("{i}");
                            }
                            eprintln!("--");
                            eprintln!("Success");
                        }
                    },
                    Err(e) => crate::handle_client_error(e, opt.output_mode),
                }
            }
            DeniedNamesOpt::Append { names } => {
                let client = opt.to_client(OpType::Write).await;

                match client.system_denied_names_append(names).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DeniedNamesOpt::Remove { names } => {
                let client = opt.to_client(OpType::Write).await;

                match client.system_denied_names_remove(names).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}
