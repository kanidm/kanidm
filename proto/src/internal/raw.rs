use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::v1::Entry;

#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Filter {
    // This is attr - value
    #[serde(alias = "Eq")]
    Eq(String, String),
    #[serde(alias = "Cnt")]
    Cnt(String, String),
    #[serde(alias = "Pres")]
    Pres(String),
    #[serde(alias = "Or")]
    #[schema(no_recursion)]
    Or(Vec<Filter>),
    #[serde(alias = "And")]
    #[schema(no_recursion)]
    And(Vec<Filter>),
    #[serde(alias = "AndNot")]
    #[schema(no_recursion)]
    AndNot(Box<Filter>),
    #[serde(rename = "self", alias = "Self")]
    SelfUuid,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Modify {
    Present(String, String),
    Removed(String, String),
    Purged(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ModifyList {
    pub mods: Vec<Modify>,
}

impl ModifyList {
    pub fn new_list(mods: Vec<Modify>) -> Self {
        ModifyList { mods }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SearchRequest {
    pub filter: Filter,
}

impl SearchRequest {
    pub fn new(filter: Filter) -> Self {
        SearchRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
}

impl SearchResponse {
    pub fn new(entries: Vec<Entry>) -> Self {
        SearchResponse { entries }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateRequest {
    pub entries: Vec<Entry>,
}

impl CreateRequest {
    pub fn new(entries: Vec<Entry>) -> Self {
        CreateRequest { entries }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DeleteRequest {
    pub filter: Filter,
}

impl DeleteRequest {
    pub fn new(filter: Filter) -> Self {
        DeleteRequest { filter }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModifyRequest {
    // Probably needs a modlist?
    pub filter: Filter,
    pub modlist: ModifyList,
}

impl ModifyRequest {
    pub fn new(filter: Filter, modlist: ModifyList) -> Self {
        ModifyRequest { filter, modlist }
    }
}

#[cfg(test)]
mod tests {
    use super::Filter as ProtoFilter;
    use crate::constants::ATTR_CLASS;

    #[test]
    fn test_protofilter_simple() {
        let pf: ProtoFilter = ProtoFilter::Pres(ATTR_CLASS.to_string());

        println!("{:?}", serde_json::to_string(&pf).expect("JSON failure"));
    }
}
