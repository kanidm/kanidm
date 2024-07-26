use crate::ScimEntry;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Member {
    value: Uuid,
    #[serde(rename = "$ref")]
    ref_: Url,
    display: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Group {
    #[serde(flatten)]
    entry: ScimEntry,

    display_name: String,
    members: Vec<Member>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RFC7643_GROUP;

    #[test]
    fn parse_group() {
        let _ = tracing_subscriber::fmt::try_init();

        let g: Group = serde_json::from_str(RFC7643_GROUP).expect("Failed to parse RFC7643_GROUP");

        tracing::trace!(?g);

        let s = serde_json::to_string_pretty(&g).expect("Failed to serialise RFC7643_USER");
        eprintln!("{}", s);
    }
}
