use kanidm_proto::v1::Group as ProtoGroup;

#[derive(Debug, Clone)]
pub struct Group {
    // name
// uuid
}

impl Group {
    /*
    pub fn new() -> Self {
        Group {}
    }
    */

    pub fn into_proto(&self) -> ProtoGroup {
        unimplemented!();
    }
}
