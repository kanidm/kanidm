use crate::{handle_client_error, OpType, SchemaClassOpt};

impl SchemaClassOpt {
    pub fn debug(&self) -> bool {
        match self {
            Self::List { copt } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            Self::List { copt } => {
                let client = copt.to_client(OpType::Read).await;

                let classes = match client.scim_schema_class_list(None).await {
                    Ok(classes) => classes,
                    Err(e) => {
                        handle_client_error(e, copt.output_mode);
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
