use kanidm_client::KanidmClient;
use kanidm_proto::constants::ATTR_DOMAIN_DISPLAY_NAME;
use kanidmd_testkit::{ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};
use kanidmd_testkit::{IDM_ADMIN_TEST_PASSWORD, IDM_ADMIN_TEST_USER};

#[kanidmd_testkit::test]
async fn test_idm_set_ldap_allow_unix_password_bind(rsclient: KanidmClient) {
    rsclient
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as admin");
    rsclient
        .idm_set_ldap_allow_unix_password_bind(true)
        .await
        .expect("Failed to set ldap allow unix password bind to true");
}
#[kanidmd_testkit::test]
async fn test_idm_domain_set_ldap_basedn(rsclient: KanidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as admin");

    rsclient
        .idm_domain_set_ldap_basedn("dc=example,dc=com")
        .await
        .expect("Failed to set idm_domain_set_ldap_basedn");
}

#[kanidmd_testkit::test]
async fn test_idm_domain_set_display_name(rsclient: KanidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as admin");

    let new_domain_display_name = "hello kanidm 12345667";

    rsclient
        .idm_domain_set_display_name(new_domain_display_name)
        .await
        .expect("Failed to set idm_domain_set_display_name");

    let domain_after = rsclient
        .idm_domain_get()
        .await
        .expect("Failed to idm_domain_get");

    assert_eq!(
        domain_after.attrs.get(ATTR_DOMAIN_DISPLAY_NAME),
        Some(&vec![new_domain_display_name.to_string()])
    );
}
