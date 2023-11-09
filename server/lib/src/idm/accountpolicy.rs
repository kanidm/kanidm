use crate::prelude::*;
use crate::value::CredentialType;
// use crate::idm::server::IdmServerProxyWriteTransaction;

#[derive(Clone)]
pub(crate) struct AccountPolicy {
    privilege_expiry: u32,
    authsession_expiry: u32,
    pw_min_length: u32,
    credential_policy: CredentialType,
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
        let pw_min_length = val
            .get_ava_single_uint32(Attribute::AuthPasswordMinimumLength)
            .unwrap_or(PW_MIN_LENGTH);

        let credential_policy = val
            .get_ava_single_credential_type(Attribute::CredentialTypeMinimum)
            .unwrap_or(CredentialType::Any);

        Some(AccountPolicy {
            privilege_expiry,
            authsession_expiry,
            pw_min_length,
            credential_policy,
        })
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Default))]
pub(crate) struct ResolvedAccountPolicy {
    privilege_expiry: u32,
    authsession_expiry: u32,
    pw_min_length: u32,
    credential_policy: CredentialType,
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
            pw_min_length: PW_MIN_LENGTH,
            credential_policy: CredentialType::Any,
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

            // Take larger pw min len
            if acc_pol.pw_min_length > accumulate.pw_min_length {
                accumulate.pw_min_length = acc_pol.pw_min_length
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
        self.pw_min_length
    }

    pub(crate) fn credential_policy(&self) -> CredentialType {
        self.credential_policy
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountPolicy, CredentialType, ResolvedAccountPolicy};
    // use crate::prelude::*;

    #[test]
    fn test_idm_account_policy_resolve() {
        let policy_a = AccountPolicy {
            privilege_expiry: 100,
            authsession_expiry: 100,
            pw_min_length: 11,
            credential_policy: CredentialType::Mfa,
        };

        let policy_b = AccountPolicy {
            privilege_expiry: 150,
            authsession_expiry: 50,
            pw_min_length: 15,
            credential_policy: CredentialType::Passkey,
        };

        let rap = ResolvedAccountPolicy::fold_from([policy_a, policy_b].into_iter());

        assert_eq!(rap.privilege_expiry(), 100);
        assert_eq!(rap.authsession_expiry(), 50);
        assert_eq!(rap.pw_min_length(), 15);
        assert_eq!(rap.credential_policy, CredentialType::Passkey);
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
