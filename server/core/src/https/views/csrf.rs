use super::cookies;
use crate::https::ServerState;
use axum_extra::extract::cookie::{CookieJar, SameSite};
use crypto_glue::{
    hex,
    hmac_s256::HmacSha256,
    rand::{self, Rng},
    traits::Mac,
};
use kanidm_proto::internal::COOKIE_CSRF_NONCE;
use serde::Deserialize;
use std::time::Duration;

const SUBMISSION_WINDOW: Duration = Duration::from_secs(30);

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
    state: &ServerState,
    jar: CookieJar,
    related_input_id: &str,
) -> Result<(CookieJar, CsrfData), ()> {
    let mut nonce: Nonce = [0; _];

    {
        let mut rng = rand::thread_rng();
        rng.fill(&mut nonce);
    }

    let jar = cookies::make_signed(state, COOKIE_CSRF_NONCE, &nonce)
        .map(|mut cookie| {
            cookie.set_same_site(SameSite::Strict);
            jar.add(cookie)
        })
        .ok_or(())?;

    let nonce_hex = hex::encode(nonce);
    let mask_hex = hex::encode(MASK.to_be_bytes());

    Ok((
        jar,
        CsrfData {
            nonce_hex,
            mask_hex,
            related_input_id: related_input_id.to_string(),
        },
    ))
}

pub(crate) fn verify_parameters(
    state: &ServerState,
    jar: &CookieJar,

    related_input: &[u8],
    solution: &CsrfSolution,

    current_time: Duration,
) -> Result<(), ()> {
    let nonce: Nonce = cookies::get_signed(state, jar, COOKIE_CSRF_NONCE).ok_or(())?;

    let timestamp = hex::decode(&solution.timestamp_hex).map_err(|_| ())?;
    let solution = hex::decode(&solution.solution_hex).map_err(|_| ())?;

    let mut client_time_bytes: [u8; 8] = [0; 8];
    if timestamp.len() != client_time_bytes.len() {
        return Err(());
    }
    client_time_bytes.copy_from_slice(&timestamp);

    let client_time = u64::from_be_bytes(client_time_bytes);
    // For some reason JS time is millis from epoch.
    let client_time = Duration::from_millis(client_time);

    let step = current_time.abs_diff(client_time);

    if step > SUBMISSION_WINDOW {
        error!("CSRF Timestamp outside of acceptable time window.");

        return Err(());
    }

    let verified = verify(&nonce, related_input, &solution, &timestamp);

    if verified {
        Ok(())
    } else {
        Err(())
    }
}

fn verify(nonce: &[u8], related: &[u8], solution: &[u8], timestamp: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(nonce) else {
        error!("Failed to process CSRF nonce to HMAC Key");
        return false;
    };

    mac.update(related);
    mac.update(solution);
    mac.update(timestamp);

    let result = mac.finalize();

    let result_bytes = result.into_bytes();

    let result_str = hex::encode(result_bytes);

    let mut buffer: [u8; 4] = [0; 4];
    if let Some(bytes) = result_bytes.get(..4) {
        buffer.copy_from_slice(bytes);
    } else {
        return false;
    }

    let result_u32 = u32::from_be_bytes(buffer) & MASK;

    debug!(?result_str, ?result_u32);

    result_u32 == 0u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solve(nonce: &[u8], input: &[u8], time: &[u8]) -> [u8; 4] {
        for solution in 0..u32::MAX {
            let solution_bytes = solution.to_be_bytes();
            if verify(nonce, input, &solution_bytes, time) {
                return solution_bytes;
            }
        }
        // Worst case, no solution found.
        unreachable!();
    }

    #[test]
    fn it_works() {
        let nonce: [u8; 32] = [0; 32];
        let time: [u8; 8] = [0; 8];
        let input = b"test";

        let solution = solve(&nonce, input, &time);

        let expected_solution: [u8; 4] = [0, 0, 0, 251];
        assert_eq!(expected_solution, solution);

        // If you change the input, the solution changes too.
        let input = b"foo";
        let solution = solve(&nonce, input, &time);

        let expected_solution: [u8; 4] = [0, 0, 10, 221];
        assert_eq!(expected_solution, solution);
    }
}
