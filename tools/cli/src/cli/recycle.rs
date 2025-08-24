use kanidm_proto::cli::OpType;
use crate::{handle_client_error, KanidmClientParser, RecycleOpt};

impl RecycleOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            RecycleOpt::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.recycle_bin_list().await {
                    Ok(r) => r.iter().for_each(|e| println!("{e}")),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            RecycleOpt::Get(nopt) => {
                let client = opt.to_client(OpType::Read).await;
                match client.recycle_bin_get(nopt.name.as_str()).await {
                    Ok(Some(e)) => println!("{e}"),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            RecycleOpt::Revive(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client.recycle_bin_revive(nopt.name.as_str()).await {
                    handle_client_error(e, opt.output_mode)
                }
            }
        }
    }
}
