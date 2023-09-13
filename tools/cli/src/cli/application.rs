use crate::common::OpType;
use crate::handle_client_error;
use crate::ApplicationOpt;

impl ApplicationOpt {
    pub fn debug(&self) -> bool {
        match self {
            ApplicationOpt::List(copt) => copt.debug,
        }
    }
    pub async fn exec(&self) {
        match self {
            ApplicationOpt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_application_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
        }
    }
}
