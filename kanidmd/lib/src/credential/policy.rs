use std::time::Duration;

use super::Password;

const PBKDF2_MIN_NIST_COST: u64 = 10000;

#[derive(Debug)]
pub struct CryptoPolicy {
    pub(crate) pbkdf2_cost: usize,
}

impl CryptoPolicy {
    #[cfg(test)]
    pub(crate) fn minimum() -> Self {
        CryptoPolicy {
            pbkdf2_cost: PBKDF2_MIN_NIST_COST as usize,
        }
    }

    pub fn time_target(t: Duration) -> Self {
        let r = match Password::bench_pbkdf2((PBKDF2_MIN_NIST_COST * 10) as usize) {
            Some(bt) => {
                let ubt = bt.as_nanos() as u64;

                // Get the cost per thousand rounds
                let per_thou = (PBKDF2_MIN_NIST_COST * 10) / 1000;
                let t_per_thou = ubt / per_thou;
                // eprintln!("{} / {}", ubt, per_thou);

                // Now we need the attacker work in nanos
                let attack_time = t.as_nanos() as u64;
                let r = (attack_time / t_per_thou) * 1000;

                // eprintln!("({} / {} ) * 1000", attack_time, t_per_thou);
                // eprintln!("Maybe rounds -> {}", r);

                if r < PBKDF2_MIN_NIST_COST {
                    PBKDF2_MIN_NIST_COST as usize
                } else {
                    r as usize
                }
            }
            None => PBKDF2_MIN_NIST_COST as usize,
        };

        CryptoPolicy { pbkdf2_cost: r }
    }
}
