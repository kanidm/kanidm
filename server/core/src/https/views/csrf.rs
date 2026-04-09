use serde::Deserialize;
// use std::time::Duration;
use crypto_glue::{
    hex,
    rand::{self, Rng},
};

// const SUBMISSION_WINDOW: Duration = Duration::from_secs(30);

#[cfg(test)]
const MASK: u32 = 0x003ff;

// 19 bits.
// (1 << 19) - 1
#[cfg(not(test))]
const MASK: u32 = 0x3ffff;

type Nonce = [u8; 32];

pub(crate) struct CsrfData {
    pub nonce_hex: String,
    pub mask_hex: String,
    pub related_input_id: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub(crate) struct CsrfSolution {
    timestamp_hex: String,
    solution_hex: String,
}

pub(crate) fn generate_parameters(
    // Probably the cookie jar which we need to update as well?
    related_input_id: &str,
) -> Result<CsrfData, ()> {
    let mut nonce: Nonce = [0; _];

    {
        let mut rng = rand::thread_rng();
        rng.fill(&mut nonce);
    }

    let nonce_hex = hex::encode(&nonce);
    let mask_hex = hex::encode(&MASK.to_be_bytes());

    Ok(CsrfData {
        nonce_hex,
        mask_hex,
        related_input_id: related_input_id.to_string(),
    })
}

/*
pub(crate) fn verify_parameters(
    // Cookie jar for the nonce?
    // nonce: Nonce,

    related_input: &[u8],
    solution: CsrfSolution,


) -> Result<(), ()> {


    warn!(?related_input, ?solution);

    Ok(())
}

*/
