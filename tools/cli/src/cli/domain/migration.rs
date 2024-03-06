use crate::common::OpType;
use crate::DomainMigrationOpt;

impl DomainMigrationOpt {
    pub fn debug(&self) -> bool {
        match self {
            DomainMigrationOpt::UpgradeCheck { copt } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            DomainMigrationOpt::UpgradeCheck { copt } => {
                let _client = copt.to_client(OpType::Write).await;

                todo!();


            }
        }
    }
}

