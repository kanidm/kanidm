use kanidmd_testkit::AsyncTestEnvironment;
use ldap3_client::LdapClientBuilder;

#[kanidmd_testkit::test(ldap = true)]
async fn test_ldap_basic_unix_bind(test_env: &AsyncTestEnvironment) {
    let ldap_url = test_env.ldap_url.as_ref().unwrap();

    let mut ldap_client = LdapClientBuilder::new(ldap_url).build().await.unwrap();

    // Bind as anonymous
    ldap_client.bind("".into(), "".into()).await.unwrap();

    let whoami = ldap_client.whoami().await.unwrap();

    assert_eq!(whoami, Some("u: anonymous@localhost".to_string()));
}
