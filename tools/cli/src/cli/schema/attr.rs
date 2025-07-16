
use crate::{
    handle_client_error,
    SchemaAttrOpt,
    OpType,
};

impl SchemaAttrOpt {
    pub fn debug(&self) -> bool {
        match self {
            Self::List { copt }
                => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            Self::List { copt } => {
                let client = copt.to_client(OpType::Read).await;

                let attrs = match client.scim_schema_attribute_list(
                    None
                ).await {
                    Ok(attrs) => attrs,
                    Err(e) => {
                        handle_client_error(e, copt.output_mode);
                        return;
                    }
                };

                for attr in attrs.resources {
                    println!("---");
                    println!("uuid: {}", attr.header.id);
                    println!("attribute_name: {}", attr.attributename);
                    println!("description: {}", attr.description);
                    println!("multivalue: {}", attr.multivalue);
                    println!("unique: {}", attr.unique);
                    println!("syntax: {}", attr.syntax);

                }
            }
        }
    }
}
