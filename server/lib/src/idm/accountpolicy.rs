use crate::prelude::*;
// use crate::idm::server::IdmServerProxyWriteTransaction;

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Default)]
#[repr(u32)]
pub(crate) enum CredentialPolicy {
    #[default]
    NoPolicy = 0,
    MfaRequired = 10,
    PasskeyRequired = 20,
    AttestedPasskeyRequired = 30,
    AttestedResidentKeyRequired = 40,
}

impl From<u32> for CredentialPolicy {
    fn from(value: u32) -> Self {
        if value >= CredentialPolicy::AttestedResidentKeyRequired as u32 {
            CredentialPolicy::AttestedResidentKeyRequired
        } else if value >= CredentialPolicy::AttestedPasskeyRequired as u32 {
            CredentialPolicy::AttestedPasskeyRequired
        } else if value >= CredentialPolicy::PasskeyRequired as u32 {
            CredentialPolicy::PasskeyRequired
        } else if value >= CredentialPolicy::MfaRequired as u32 {
            CredentialPolicy::MfaRequired
        } else {
            CredentialPolicy::NoPolicy
        }
    }
}

#[derive(Clone)]
pub(crate) struct AccountPolicy {
    privilege_expiry: u32,
    authsession_expiry: u32,
    credential_policy: CredentialPolicy,
}

impl From<&EntrySealedCommitted> for Option<AccountPolicy> {
    fn from(val: &EntrySealedCommitted) -> Self {
        if !val.attribute_equality(
            Attribute::Class,
            &EntryClass::AccountPolicy.to_partialvalue(),
        ) {
            return None;
        }

        let authsession_expiry = val
            .get_ava_single_uint32(Attribute::AuthSessionExpiry)
            .unwrap_or(MAXIMUM_AUTH_SESSION_EXPIRY);
        let privilege_expiry = val
            .get_ava_single_uint32(Attribute::PrivilegeExpiry)
            .unwrap_or(MAXIMUM_AUTH_PRIVILEGE_EXPIRY);
        let credential_policy = CredentialPolicy::default();

        Some(AccountPolicy {
            privilege_expiry,
            authsession_expiry,
            credential_policy,
        })
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Default))]
pub(crate) struct ResolvedAccountPolicy {
    privilege_expiry: u32,
    authsession_expiry: u32,
    credential_policy: CredentialPolicy,
}

impl ResolvedAccountPolicy {
    pub(crate) fn fold_from<I>(iter: I) -> Self
    where
        I: Iterator<Item = AccountPolicy>,
    {
        // Start with our maximums
        let mut accumulate = ResolvedAccountPolicy {
            privilege_expiry: MAXIMUM_AUTH_PRIVILEGE_EXPIRY,
            authsession_expiry: MAXIMUM_AUTH_SESSION_EXPIRY,
            credential_policy: CredentialPolicy::default(),
        };

        iter.for_each(|acc_pol| {
            // Take the smaller expiry
            if acc_pol.privilege_expiry < accumulate.privilege_expiry {
                accumulate.privilege_expiry = acc_pol.privilege_expiry
            }

            // Take the smaller expiry
            if acc_pol.authsession_expiry < accumulate.authsession_expiry {
                accumulate.authsession_expiry = acc_pol.authsession_expiry
            }

            // Take the greater credential type policy
            if acc_pol.credential_policy > accumulate.credential_policy {
                accumulate.credential_policy = acc_pol.credential_policy
            }
        });

        accumulate
    }

    pub(crate) fn privilege_expiry(&self) -> u32 {
        self.privilege_expiry
    }

    pub(crate) fn authsession_expiry(&self) -> u32 {
        self.authsession_expiry
    }

    pub(crate) fn pw_min_length(&self) -> u32 {
        PW_MIN_LENGTH
    }

    /*
    pub(crate) fn credential_policy(&self) -> CredentialPolicy {
        self.credential_policy
    }
    */
}

#[cfg(test)]
mod tests {
    use super::{AccountPolicy, CredentialPolicy, ResolvedAccountPolicy};
    // use crate::prelude::*;

    #[test]
    fn test_idm_account_policy_resolve() {
        let policy_a = AccountPolicy {
            privilege_expiry: 100,
            authsession_expiry: 100,
            credential_policy: CredentialPolicy::MfaRequired,
        };

        let policy_b = AccountPolicy {
            privilege_expiry: 150,
            authsession_expiry: 50,
            credential_policy: CredentialPolicy::PasskeyRequired,
        };

        let rap = ResolvedAccountPolicy::fold_from([policy_a, policy_b].into_iter());

        assert_eq!(rap.privilege_expiry(), 100);
        assert_eq!(rap.authsession_expiry(), 50);
        assert_eq!(rap.credential_policy, CredentialPolicy::PasskeyRequired);
    }

    /*
    #[idm_test]
    async fn test_idm_account_policy_load(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        todo!();
    }
    */
}
