use crate::common::OpType;
use crate::{handle_client_error, RecycleOpt};

impl RecycleOpt {
    pub fn debug(&self) -> bool {
        match self {
            RecycleOpt::List(copt) => copt.debug,
            RecycleOpt::Get(nopt) => nopt.copt.debug,
            RecycleOpt::Revive(nopt) => nopt.copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            RecycleOpt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.recycle_bin_list().await {
                    Ok(r) => r.iter().for_each(|e| println!("{}", e)),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            RecycleOpt::Get(nopt) => {
                let client = nopt.copt.to_client(OpType::Read).await;
                match client.recycle_bin_get(nopt.name.as_str()).await {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            RecycleOpt::Revive(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                if let Err(e) = client.recycle_bin_revive(nopt.name.as_str()).await {
                    handle_client_error(e, nopt.copt.output_mode)
                }
            }
        }
    }
}
