use crate::common::OpType;
use crate::handle_client_error;
use crate::ApplicationOpt;

impl ApplicationOpt {
    pub fn debug(&self) -> bool {
        match self {
            ApplicationOpt::List(copt) => copt.debug,
            ApplicationOpt::Create(nopt) => nopt.copt.debug,
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
            ApplicationOpt::Create(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client.idm_application_create(nopt.name.as_str()).await {
                    Ok(_) => println!("Application {} successfully created.", &nopt.name),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
        }
    }
}
