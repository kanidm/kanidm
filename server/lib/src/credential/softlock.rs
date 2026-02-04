//! Represents a temporary denial of the credential to authenticate. This is used
//! to ratelimit and prevent bruteforcing of accounts. At an initial failure the
//! SoftLock is created and the count set to 1, with a unlock_at set to 1 second
//! later, and a reset_count_at: at a maximum time window for a cycle.
//!
//! If the softlock already exists, and the failure count is 0, then this acts as the
//! creation where the reset_count_at window is then set.
//!
//! While current_time < unlock_at, all authentication attempts are denied with a
//! message regarding the account being temporarily unavailable. Once
//! unlock_at < current_time, authentication will be processed again. If a subsequent
//! failure occurs, unlock_at is extended based on policy, and failure_count incremented.
//!
//! If unlock_at < current_time, and authentication succeeds the login is allowed
//! and no changes to failure_count or unlock_at are made.
//!
//! If reset_count_at < current_time, then failure_count is reset to 0 before processing.
//!
//! This allows handling of max_failure_count, so that when that value from policy is
//! exceeded then unlock_at is set to reset_count_at to softlock until the cycle
//! is over (see NIST sp800-63b.). For example, reset_count_at will be 24 hours after
//! the first failed authentication attempt.
//!
//! This also works for something like TOTP which allows a 60 second cycle for the
//! reset_count_at and a max number of attempts in that window (say 5). with short
//! delays in between (1 second).
//!
//! ```text
//!
//!                                                  ┌────────────────────────┐
//!                                                  │reset_at < current_time │
//!                                                 ─└────────────────────────┘
//!                                                │                         │
//!                                                ▼
//!             ┌─────┐                         .─────.       ┌────┐         │
//!             │Valid│                        ╱       ╲      │Fail│
//!        ┌────┴─────┴───────────────────────(count = 0)─────┴────┴┐        │
//!        │                                   `.     ,'            │
//!        │                                     `───'              │        │
//!        │             ┌────────────────────────┐▲                │
//!        │             │reset_at < current_time │                 │        │
//!        │             └────────────────────────┘│                │
//!        │                      ┌ ─ ─ ─ ─ ─ ─ ─ ─                 │        │
//!        │                                                        │
//!        │                      ├─────┬───────┬──┐                ▼        │
//!        │                      │     │ Fail  │  │             .─────.
//!        │                      │     │count++│  │           ,'       `.   │
//!        ▼                   .─────.  └───────┘  │          ;  Locked   :
//! ┌────────────┐            ╱       ╲            └─────────▶: count > 0 ;◀─┤
//! │Auth Success│◀─┬─────┬──(Unlocked )                       ╲         ╱   │
//! └────────────┘  │Valid│   `.     ,'                         `.     ,'    │
//!                 └─────┘     `───'                             `───'      │
//!                               ▲                                 │        │
//!                               │                                 │        │
//!                               └─────┬──────────────────────────┬┴┬───────┴──────────────────┐
//!                                     │ expire_at < current_time │ │ current_time < expire_at │
//!                                     └──────────────────────────┘ └──────────────────────────┘
//!
//! ```
//!

use std::time::Duration;

const ONEDAY: u64 = 86400;

#[derive(Debug, Clone)]
pub enum CredSoftLockPolicy {
    Password,
    Totp(u64),
    Webauthn,
    Unrestricted,
}

impl CredSoftLockPolicy {
    /// Determine the next lock state after a failure based on this credentials
    /// policy.
    fn failure_next_state(&self, count: usize, ct: Duration) -> LockState {
        match self {
            CredSoftLockPolicy::Password => {
                let next_day_end = ct.as_secs() + ONEDAY;
                let rem = next_day_end % ONEDAY;
                let reset_at = Duration::from_secs(next_day_end - rem);

                if count < 3 {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at: ct + Duration::from_secs(1),
                    }
                } else if count < 9 {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at: ct + Duration::from_secs(3),
                    }
                } else if count < 25 {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at: ct + Duration::from_secs(5),
                    }
                } else if count < 100 {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at: ct + Duration::from_secs(10),
                    }
                } else {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at: reset_at,
                    }
                }
            }
            CredSoftLockPolicy::Totp(step) => {
                // reset at is based on the next step ending.
                let next_window_end = ct.as_secs() + step;
                let rem = next_window_end % step;
                let reset_at = Duration::from_secs(next_window_end - rem);
                // We delay for 1 second, unless count is > 3, then we set
                // unlock at to reset_at.
                if count >= 3 {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at: reset_at,
                    }
                } else {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at: ct + Duration::from_secs(1),
                    }
                }
            }
            CredSoftLockPolicy::Webauthn => {
                // we only lock for 1 second to slow them down.
                // TODO: Could this be a DOS/Abuse vector?
                LockState::Locked {
                    count,
                    reset_at: ct + Duration::from_secs(1),
                    unlock_at: ct + Duration::from_secs(1),
                }
            }
            CredSoftLockPolicy::Unrestricted => {
                // No action needed
                LockState::Init
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LockState {
    Init,
    // count
    // * Number of Failures in this cycle
    // unlock_at
    // * Time of next allowed check (works with delay)
    // reset_count_at
    // * The time to reset the state to init.
    //     count  reset_at  unlock_at
    Locked {
        count: usize,
        reset_at: Duration,
        unlock_at: Duration,
    },
    Unlocked(usize, Duration),
}

#[derive(Debug, Clone)]
pub(crate) struct CredSoftLock {
    state: LockState,
    // Policy (for determining delay times based on num failures, and when to reset?)
    policy: CredSoftLockPolicy,
    last_expire_at: Duration,
}

impl CredSoftLock {
    pub fn new(policy: CredSoftLockPolicy) -> Self {
        CredSoftLock {
            state: LockState::Init,
            policy,
            last_expire_at: Duration::from_secs(0),
        }
    }

    pub fn apply_time_step(&mut self, ct: Duration, expire_at: Option<Duration>) {
        // Do a reset if needed?
        let mut next_state = match self.state {
            LockState::Init => LockState::Init,
            LockState::Locked {
                count,
                mut reset_at,
                unlock_at,
            } => {
                // If there is a softlock expiry time, then we use it to *bound* the reset_at time.
                // That way the remaining logic will kick in and then move the reset_at.
                if let Some(expiry) = expire_at {
                    if self.last_expire_at != expiry {
                        // This lets us track former expiration times. We should only apply the reset ONCE.
                        self.last_expire_at = expiry;

                        // Now, we have to choose *if* we actually do a reset.
                        if reset_at > expiry {
                            // Okay, so the reset_at is beyond the expiry, we cap it now. This can
                            // either cause a reset, or the reset_at to be bound to expiry in the unlock state.
                            //
                            // for example, consider someone set expiry into the future. Then we don't
                            // actually want this to DO anything, because that wouldn't help anyone.
                            reset_at = expiry
                        }
                    }
                }

                if ct > reset_at {
                    LockState::Init
                } else if ct > unlock_at {
                    LockState::Unlocked(count, reset_at)
                } else {
                    LockState::Locked {
                        count,
                        reset_at,
                        unlock_at,
                    }
                }
            }
            LockState::Unlocked(count, reset_at) => {
                if ct > reset_at {
                    LockState::Init
                } else {
                    LockState::Unlocked(count, reset_at)
                }
            }
        };
        std::mem::swap(&mut self.state, &mut next_state);
    }

    /// Is this credential valid to proceed at this point in time.
    pub fn is_valid(&self) -> bool {
        !matches!(self.state, LockState::Locked { .. })
    }

    /// Document a failure of authentication at this time.
    pub fn record_failure(&mut self, ct: Duration) {
        let mut next_state = match self.state {
            LockState::Init => {
                self.policy.failure_next_state(1, ct)
                // LockState::Locked(1, reset_at, unlock_at)
            }
            LockState::Locked {
                count,
                reset_at: _,
                unlock_at: _,
            } => {
                // We should never reach this but just in case ...
                self.policy.failure_next_state(count + 1, ct)
                // LockState::Locked(count + 1, reset_at, unlock_at)
            }
            LockState::Unlocked(count, _reset_at) => {
                self.policy.failure_next_state(count + 1, ct)
                // LockState::Locked(count + 1, reset_at, unlock_at)
            }
        };
        std::mem::swap(&mut self.state, &mut next_state);
    }

    #[cfg(test)]
    pub fn is_state_init(&self) -> bool {
        matches!(self.state, LockState::Init)
    }

    #[cfg(test)]
    fn peek_state(&self) -> &LockState {
        &self.state
    }

    /*
    #[cfg(test)]
    fn set_failure_count(&mut self, count: usize) {
        let mut next_state = match self.state {
            LockState::Init => panic!(),
            LockState::Locked(_count, reset_at, unlock_at) => {
                LockState::Locked(count, reset_at, unlock_at)
            }
            LockState::Unlocked(count, reset_at) => {
                LockState::Unlocked(count, reset_at)
            }
        };
        std::mem::swap(&mut self.state, &mut next_state);
    }
    */
}

#[cfg(test)]
mod tests {
    use crate::credential::softlock::*;
    use crate::credential::totp::TOTP_DEFAULT_STEP;

    #[test]
    fn test_credential_softlock_statemachine() {
        // Check that given the set of inputs, correct decisions about
        // locking are made, and the states can be moved through.
        // ==> Check the init state.
        let mut slock = CredSoftLock::new(CredSoftLockPolicy::Password);
        assert!(slock.is_state_init());
        assert!(slock.is_valid());
        // A success does nothing, so we don't track them.
        let ct = Duration::from_secs(10);
        // Generate a failure
        // ==> trans to locked
        slock.record_failure(ct);
        assert!(
            slock.peek_state()
                == &LockState::Locked {
                    count: 1,
                    reset_at: Duration::from_secs(ONEDAY),
                    unlock_at: Duration::from_secs(10 + 1)
                }
        );
        // It will now fail
        // ==> trans ct < exp_at
        slock.apply_time_step(ct, None);
        assert!(!slock.is_valid());
        // A few seconds later it will be okay.
        // ==> trans ct < exp_at
        let ct2 = ct + Duration::from_secs(2);
        slock.apply_time_step(ct2, None);
        assert!(slock.is_valid());
        // Now trigger a failure now, we move back to locked.
        // ==> trans fail unlock -> lock
        slock.record_failure(ct2);
        assert!(
            slock.peek_state()
                == &LockState::Locked {
                    count: 2,
                    reset_at: Duration::from_secs(ONEDAY),
                    unlock_at: Duration::from_secs(10 + 3)
                }
        );
        assert!(!slock.is_valid());
        // Now check the reset_at behaviour. We need to check a locked and unlocked state.
        let mut slock2 = slock.clone();
        // This triggers the reset at from locked.
        // ==> trans locked -> init
        let ct3 = ct + Duration::from_secs(ONEDAY + 2);
        slock.apply_time_step(ct3, None);
        assert!(slock.is_state_init());
        assert!(slock.is_valid());
        // For slock2, we move to unlocked:
        // ==> trans unlocked -> init
        let ct4 = ct2 + Duration::from_secs(2);
        slock2.apply_time_step(ct4, None);
        eprintln!("{:?}", slock2.peek_state());
        assert_eq!(
            slock2.peek_state(),
            &LockState::Unlocked(2, Duration::from_secs(ONEDAY))
        );
        slock2.apply_time_step(ct3, None);
        assert!(slock2.is_state_init());
        assert!(slock2.is_valid());
    }

    #[test]
    fn test_credential_softlock_policy_password() {
        let policy = CredSoftLockPolicy::Password;

        assert!(
            policy.failure_next_state(1, Duration::from_secs(0))
                == LockState::Locked {
                    count: 1,
                    reset_at: Duration::from_secs(ONEDAY),
                    unlock_at: Duration::from_secs(1)
                }
        );

        assert!(
            policy.failure_next_state(8, Duration::from_secs(0))
                == LockState::Locked {
                    count: 8,
                    reset_at: Duration::from_secs(ONEDAY),
                    unlock_at: Duration::from_secs(3)
                }
        );

        assert!(
            policy.failure_next_state(24, Duration::from_secs(0))
                == LockState::Locked {
                    count: 24,
                    reset_at: Duration::from_secs(ONEDAY),
                    unlock_at: Duration::from_secs(5)
                }
        );

        assert!(
            policy.failure_next_state(99, Duration::from_secs(0))
                == LockState::Locked {
                    count: 99,
                    reset_at: Duration::from_secs(ONEDAY),
                    unlock_at: Duration::from_secs(10)
                }
        );

        assert!(
            policy.failure_next_state(100, Duration::from_secs(0))
                == LockState::Locked {
                    count: 100,
                    reset_at: Duration::from_secs(ONEDAY),
                    unlock_at: Duration::from_secs(ONEDAY)
                }
        );
    }

    #[test]
    fn test_credential_softlock_policy_totp() {
        let policy = CredSoftLockPolicy::Totp(TOTP_DEFAULT_STEP);

        assert!(
            policy.failure_next_state(1, Duration::from_secs(10))
                == LockState::Locked {
                    count: 1,
                    reset_at: Duration::from_secs(TOTP_DEFAULT_STEP),
                    unlock_at: Duration::from_secs(11)
                }
        );

        assert!(
            policy.failure_next_state(2, Duration::from_secs(10))
                == LockState::Locked {
                    count: 2,
                    reset_at: Duration::from_secs(TOTP_DEFAULT_STEP),
                    unlock_at: Duration::from_secs(11)
                }
        );

        assert!(
            policy.failure_next_state(3, Duration::from_secs(10))
                == LockState::Locked {
                    count: 3,
                    reset_at: Duration::from_secs(TOTP_DEFAULT_STEP),
                    unlock_at: Duration::from_secs(TOTP_DEFAULT_STEP)
                }
        );
    }

    #[test]
    fn test_credential_softlock_policy_webauthn() {
        let policy = CredSoftLockPolicy::Webauthn;

        assert!(
            policy.failure_next_state(1, Duration::from_secs(0))
                == LockState::Locked {
                    count: 1,
                    reset_at: Duration::from_secs(1),
                    unlock_at: Duration::from_secs(1)
                }
        );

        // No matter how many failures, webauthn always only delays by 1 second.
        assert!(
            policy.failure_next_state(1000, Duration::from_secs(0))
                == LockState::Locked {
                    count: 1000,
                    reset_at: Duration::from_secs(1),
                    unlock_at: Duration::from_secs(1)
                }
        );
    }

    #[test]
    fn test_credential_softlock_expire_at_aka_reset() {
        // test the behaviour of the expire at.
        let mut slock = CredSoftLock::new(CredSoftLockPolicy::Password);
        assert!(slock.is_state_init());
        assert!(slock.is_valid());

        let ct = Duration::from_secs(10);
        // Generate a failure
        // ==> trans to locked
        slock.record_failure(ct);
        assert_eq!(
            slock.peek_state(),
            &LockState::Locked {
                count: 1,
                reset_at: Duration::from_secs(ONEDAY),
                unlock_at: Duration::from_secs(10 + 1)
            }
        );

        // We're in a failed state now, so we can now trigger the reset behaviour.
        slock.apply_time_step(ct, None);

        // Changes nothing.
        assert_eq!(
            slock.peek_state(),
            &LockState::Locked {
                count: 1,
                reset_at: Duration::from_secs(ONEDAY),
                unlock_at: Duration::from_secs(10 + 1)
            }
        );

        // Now, if we set the expiry to now, the lock still stays.
        slock.apply_time_step(ct, Some(Duration::from_secs(10)));
        assert_eq!(
            slock.peek_state(),
            &LockState::Locked {
                count: 1,
                reset_at: Duration::from_secs(10), // <<-- Notice the reset_at time has now shifted.
                unlock_at: Duration::from_secs(10 + 1)
            }
        );

        // But step forward, and we reset.
        let ct = Duration::from_secs(11);
        slock.apply_time_step(ct, None);
        assert_eq!(slock.peek_state(), &LockState::Init);

        // Now we record a new failure, we should be locked again.
        slock.record_failure(ct);

        assert_eq!(
            slock.peek_state(),
            &LockState::Locked {
                count: 1,
                reset_at: Duration::from_secs(ONEDAY),
                unlock_at: Duration::from_secs(11 + 1)
            }
        );

        // And the time state doesn't change that.
        slock.apply_time_step(ct, Some(Duration::from_secs(10)));

        assert_eq!(
            slock.peek_state(),
            &LockState::Locked {
                count: 1,
                reset_at: Duration::from_secs(ONEDAY),
                unlock_at: Duration::from_secs(11 + 1)
            }
        );
    }
}
