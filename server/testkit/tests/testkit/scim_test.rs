use compact_jwt::{traits::JwsVerifiable, JwsCompact, JwsEs256Verifier, JwsVerifier};
use kanidm_client::KanidmClient;
use kanidm_proto::internal::ScimSyncToken;
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidmd_lib::constants::NAME_IDM_ADMINS;
use kanidmd_lib::prelude::Attribute;
use kanidmd_testkit::{ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};
use std::str::FromStr;
use url::Url;

#[kanidmd_testkit::test]
async fn test_sync_account_lifecycle(rsclient: &KanidmClient) {
    let a_res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(a_res.is_ok());

    let a_list = rsclient.idm_sync_account_list().await.unwrap();
    assert!(a_list.is_empty());

    rsclient
        .idm_sync_account_create("ipa_sync_account", Some("Demo of a sync account"))
        .await
        .unwrap();

    let a_list = rsclient.idm_sync_account_list().await.unwrap();
    assert!(!a_list.is_empty());

    let a = rsclient
        .idm_sync_account_get("ipa_sync_account")
        .await
        .unwrap();

    let sync_entry = a.expect("No sync account was created?!");

    // Shouldn't have a cred portal.
    assert!(!sync_entry.attrs.contains_key("sync_credential_portal"));

    let url = Url::parse("https://sink.ipa.example.com/reset").unwrap();

    // Set our credential portal.
    rsclient
        .idm_sync_account_set_credential_portal("ipa_sync_account", Some(&url))
        .await
        .unwrap();

    let a = rsclient
        .idm_sync_account_get("ipa_sync_account")
        .await
        .unwrap();

    let sync_entry = a.expect("No sync account present?");
    // Should have a cred portal.

    let url_a = sync_entry
        .attrs
        .get("sync_credential_portal")
        .and_then(|x| x.first());

    assert_eq!(
        url_a.map(|s| s.as_str()),
        Some("https://sink.ipa.example.com/reset")
    );

    // Also check we can get it direct
    let url_b = rsclient
        .idm_sync_account_get_credential_portal("ipa_sync_account")
        .await
        .unwrap();

    assert_eq!(url_b, Some(url));

    // Get a token
    let token = rsclient
        .idm_sync_account_generate_token("ipa_sync_account", "token_label")
        .await
        .expect("Failed to generate token");

    let token_unverified = JwsCompact::from_str(&token).expect("Failed to parse apitoken");

    let key_id = token_unverified
        .kid()
        .expect("token does not have a key id");
    assert!(token_unverified.get_jwk_pubkey().is_none());

    let jwk = rsclient
        .get_public_jwk(key_id)
        .await
        .expect("Unable to get jwk");

    let jws_verifier = JwsEs256Verifier::try_from(&jwk).expect("Unable to build verifier");

    let token = jws_verifier
        .verify(&token_unverified)
        .map(|jws| jws.from_json::<ScimSyncToken>().expect("Invalid json"))
        .expect("Unable verify token");

    println!("{:?}", token);

    rsclient
        .idm_sync_account_destroy_token("ipa_sync_account")
        .await
        .expect("Failed to destroy token");
}

#[kanidmd_testkit::test]
async fn test_scim_sync_entry_get(rsclient: &KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // All admin to create persons.
    rsclient
        .idm_group_add_members(NAME_IDM_ADMINS, &["admin"])
        .await
        .unwrap();

    rsclient
        .idm_person_account_create("demo_account", "Deeeeemo")
        .await
        .unwrap();

    // This will be as raw json, not the strongly typed version the server sees
    // internally.
    let scim_entry = rsclient
        .scim_v1_entry_get("demo_account", None)
        .await
        .unwrap();

    tracing::info!("{:#?}", scim_entry);

    assert!(scim_entry.attrs.contains_key(&Attribute::Class));
    assert!(scim_entry.attrs.contains_key(&Attribute::Name));
    assert_eq!(
        scim_entry
            .attrs
            .get(&Attribute::Name)
            .and_then(|v| v.as_str())
            .unwrap(),
        "demo_account".to_string()
    );

    // Limit the attributes we want.
    let query = ScimEntryGetQuery {
        attributes: Some(vec![Attribute::Name]),
        ..Default::default()
    };

    let scim_entry = rsclient
        .scim_v1_entry_get("demo_account", Some(query))
        .await
        .unwrap();

    tracing::info!("{:#?}", scim_entry);

    // Should not be present now.
    assert!(!scim_entry.attrs.contains_key(&Attribute::Class));
    assert!(scim_entry.attrs.contains_key(&Attribute::Name));

    // ==========================================
    // Same, but via the Person API
    let scim_entry = rsclient
        .scim_v1_person_get("demo_account", None)
        .await
        .unwrap();

    tracing::info!("{:#?}", scim_entry);

    assert!(scim_entry.attrs.contains_key(&Attribute::Class));
    assert!(scim_entry.attrs.contains_key(&Attribute::Name));
    assert_eq!(
        scim_entry
            .attrs
            .get(&Attribute::Name)
            .and_then(|v| v.as_str())
            .unwrap(),
        "demo_account".to_string()
    );

    // Limit the attributes we want.
    let query = ScimEntryGetQuery {
        attributes: Some(vec![Attribute::Name]),
        ..Default::default()
    };

    let scim_entry = rsclient
        .scim_v1_person_get("demo_account", Some(query))
        .await
        .unwrap();

    tracing::info!("{:#?}", scim_entry);

    // Should not be present now.
    assert!(!scim_entry.attrs.contains_key(&Attribute::Class));
    assert!(scim_entry.attrs.contains_key(&Attribute::Name));
}
