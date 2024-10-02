use crate::prelude::*;
use crate::value::CredentialType;
use webauthn_rs::prelude::AttestationCaList;

#[derive(Clone)]
#[cfg_attr(test, derive(Default))]
pub(crate) struct AccountPolicy {
    privilege_expiry: u32,
    authsession_expiry: u32,
    pw_min_length: u32,
    credential_policy: CredentialType,
    webauthn_att_ca_list: Option<AttestationCaList>,
    limit_search_max_filter_test: Option<u64>,
    limit_search_max_results: Option<u64>,
    allow_primary_cred_fallback: Option<bool>,
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

        let webauthn_att_ca_list = val
            .get_ava_webauthn_attestation_ca_list(Attribute::WebauthnAttestationCaList)
            .cloned();

        let limit_search_max_results = val
            .get_ava_single_uint32(Attribute::LimitSearchMaxResults)
            .map(|u| u as u64);

        let limit_search_max_filter_test = val
            .get_ava_single_uint32(Attribute::LimitSearchMaxFilterTest)
            .map(|u| u as u64);

        let allow_primary_cred_fallback =
            val.get_ava_single_bool(Attribute::AllowPrimaryCredFallback);

        Some(AccountPolicy {
            privilege_expiry,
            authsession_expiry,
            pw_min_length,
            credential_policy,
            webauthn_att_ca_list,
            limit_search_max_filter_test,
            limit_search_max_results,
            allow_primary_cred_fallback,
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
    webauthn_att_ca_list: Option<AttestationCaList>,
    limit_search_max_filter_test: Option<u64>,
    limit_search_max_results: Option<u64>,
    allow_primary_cred_fallback: Option<bool>,
}

impl ResolvedAccountPolicy {
    #[cfg(test)]
    pub(crate) fn test_policy() -> Self {
        ResolvedAccountPolicy {
            privilege_expiry: DEFAULT_AUTH_PRIVILEGE_EXPIRY,
            authsession_expiry: DEFAULT_AUTH_SESSION_EXPIRY,
            pw_min_length: PW_MIN_LENGTH,
            credential_policy: CredentialType::Any,
            webauthn_att_ca_list: None,
            limit_search_max_filter_test: Some(DEFAULT_LIMIT_SEARCH_MAX_FILTER_TEST),
            limit_search_max_results: Some(DEFAULT_LIMIT_SEARCH_MAX_RESULTS),
            allow_primary_cred_fallback: None,
        }
    }

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
            webauthn_att_ca_list: None,
            limit_search_max_filter_test: None,
            limit_search_max_results: None,
            allow_primary_cred_fallback: None,
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

            if let Some(pol_lim) = acc_pol.limit_search_max_results {
                if let Some(acc_lim) = accumulate.limit_search_max_results {
                    if pol_lim > acc_lim {
                        accumulate.limit_search_max_results = Some(pol_lim);
                    }
                } else {
                    accumulate.limit_search_max_results = Some(pol_lim);
                }
            }

            if let Some(pol_lim) = acc_pol.limit_search_max_filter_test {
                if let Some(acc_lim) = accumulate.limit_search_max_filter_test {
                    if pol_lim > acc_lim {
                        accumulate.limit_search_max_filter_test = Some(pol_lim);
                    }
                } else {
                    accumulate.limit_search_max_filter_test = Some(pol_lim);
                }
            }

            if let Some(acc_pol_w_att_ca) = acc_pol.webauthn_att_ca_list {
                if let Some(res_w_att_ca) = accumulate.webauthn_att_ca_list.as_mut() {
                    res_w_att_ca.intersection(&acc_pol_w_att_ca);
                } else {
                    accumulate.webauthn_att_ca_list = Some(acc_pol_w_att_ca);
                }
            }

            if let Some(allow_primary_cred_fallback) = acc_pol.allow_primary_cred_fallback {
                accumulate.allow_primary_cred_fallback =
                    match accumulate.allow_primary_cred_fallback {
                        Some(acc_fallback) => Some(allow_primary_cred_fallback && acc_fallback),
                        None => Some(allow_primary_cred_fallback),
                    };
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

    pub(crate) fn webauthn_attestation_ca_list(&self) -> Option<&AttestationCaList> {
        self.webauthn_att_ca_list.as_ref()
    }

    pub(crate) fn limit_search_max_results(&self) -> Option<u64> {
        self.limit_search_max_results
    }

    pub(crate) fn limit_search_max_filter_test(&self) -> Option<u64> {
        self.limit_search_max_filter_test
    }

    pub(crate) fn allow_primary_cred_fallback(&self) -> Option<bool> {
        self.allow_primary_cred_fallback
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountPolicy, CredentialType, ResolvedAccountPolicy};
    use crate::prelude::*;
    use webauthn_rs_core::proto::AttestationCaListBuilder;

    #[test]
    fn test_idm_account_policy_resolve() {
        sketching::test_init();

        // Yubico U2F Root CA Serial 457200631
        let ca_root_a: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
-----END CERTIFICATE-----";

        // Defunct Apple WebAuthn Root CA
        let ca_root_b: &[u8] = b"-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----";

        let aaguid_a = Uuid::new_v4();
        let aaguid_b = Uuid::new_v4();
        let aaguid_c = Uuid::new_v4();
        let aaguid_d = Uuid::new_v4();
        let aaguid_e = Uuid::new_v4();

        let mut att_ca_builder = AttestationCaListBuilder::new();

        att_ca_builder
            .insert_device_pem(ca_root_a, aaguid_a, "A".to_string(), Default::default())
            .unwrap();
        att_ca_builder
            .insert_device_pem(ca_root_a, aaguid_b, "B".to_string(), Default::default())
            .unwrap();
        att_ca_builder
            .insert_device_pem(ca_root_a, aaguid_c, "C".to_string(), Default::default())
            .unwrap();
        att_ca_builder
            .insert_device_pem(ca_root_b, aaguid_d, "D".to_string(), Default::default())
            .unwrap();

        let att_ca_list_a = att_ca_builder.build();

        let policy_a = AccountPolicy {
            privilege_expiry: 100,
            authsession_expiry: 100,
            pw_min_length: 11,
            credential_policy: CredentialType::Mfa,
            webauthn_att_ca_list: Some(att_ca_list_a),
            limit_search_max_filter_test: Some(10),
            limit_search_max_results: Some(10),
            allow_primary_cred_fallback: None,
        };

        let mut att_ca_builder = AttestationCaListBuilder::new();

        att_ca_builder
            .insert_device_pem(ca_root_a, aaguid_b, "B".to_string(), Default::default())
            .unwrap();
        att_ca_builder
            .insert_device_pem(ca_root_b, aaguid_e, "E".to_string(), Default::default())
            .unwrap();

        let att_ca_list_b = att_ca_builder.build();

        let policy_b = AccountPolicy {
            privilege_expiry: 150,
            authsession_expiry: 50,
            pw_min_length: 15,
            credential_policy: CredentialType::Passkey,
            webauthn_att_ca_list: Some(att_ca_list_b),
            limit_search_max_filter_test: Some(5),
            limit_search_max_results: Some(15),
            allow_primary_cred_fallback: Some(false),
        };

        let rap = ResolvedAccountPolicy::fold_from([policy_a, policy_b].into_iter());

        assert_eq!(rap.privilege_expiry(), 100);
        assert_eq!(rap.authsession_expiry(), 50);
        assert_eq!(rap.pw_min_length(), 15);
        assert_eq!(rap.credential_policy, CredentialType::Passkey);
        assert_eq!(rap.limit_search_max_results(), Some(15));
        assert_eq!(rap.limit_search_max_filter_test(), Some(10));
        assert_eq!(rap.allow_primary_cred_fallback(), Some(false));

        let mut att_ca_builder = AttestationCaListBuilder::new();

        att_ca_builder
            .insert_device_pem(ca_root_a, aaguid_b, "B".to_string(), Default::default())
            .unwrap();

        let att_ca_list_ex = att_ca_builder.build();

        assert_eq!(rap.webauthn_att_ca_list, Some(att_ca_list_ex));
    }
}
