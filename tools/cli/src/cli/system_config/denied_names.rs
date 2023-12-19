use crate::common::OpType;

use crate::{handle_client_error, DeniedNamesOpt};

impl DeniedNamesOpt {
    pub fn debug(&self) -> bool {
        match self {
            DeniedNamesOpt::Show { copt }
            | DeniedNamesOpt::Append { copt, .. }
            | DeniedNamesOpt::Remove { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            DeniedNamesOpt::Show { copt } => {
                let client = copt.to_client(OpType::Read).await;
                match client.system_denied_names_get().await {
                    Ok(list) => {
                        for i in list {
                            println!("{}", i);
                        }
                        eprintln!("--");
                        eprintln!("Success");
                    }
                    Err(e) => crate::handle_client_error(e, copt.output_mode),
                }
            }
            DeniedNamesOpt::Append { copt, names } => {
                let client = copt.to_client(OpType::Write).await;

                match client.system_denied_names_append(names).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            DeniedNamesOpt::Remove { copt, names } => {
                let client = copt.to_client(OpType::Write).await;

                match client.system_denied_names_remove(names).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
        }
    }
}
