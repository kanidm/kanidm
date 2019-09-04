use rsidm_proto::v1::Claim as ProtoClaim;

#[derive(Debug)]
pub struct Claim {
    // For now, empty. Later we'll flesh this out to uuid + name?
}

impl Claim {
    /*
    pub fn new() -> Self {
        Claim {
            // Fill this in!
        }
    }
    */

    pub fn into_proto(&self) -> ProtoClaim {
        unimplemented!();
    }
}
