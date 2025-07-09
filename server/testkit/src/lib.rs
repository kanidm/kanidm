#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::internal::{CURegState, Filter, Modify, ModifyList};
use kanidmd_core::config::{Configuration, IntegrationTestConfig};
use kanidmd_core::{create_server_core, CoreHandle};
use kanidmd_lib::prelude::{Attribute, NAME_SYSTEM_ADMINS};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::task;
use tracing::error;
use url::Url;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::WebauthnAuthenticator;

pub const ADMIN_TEST_USER: &str = "admin";
pub const ADMIN_TEST_PASSWORD: &str = "integration test admin password";
pub const IDM_ADMIN_TEST_USER: &str = "idm_admin";
pub const IDM_ADMIN_TEST_PASSWORD: &str = "integration idm admin password";

pub const NOT_ADMIN_TEST_USERNAME: &str = "krab_test_user";
pub const NOT_ADMIN_TEST_PASSWORD: &str = "eicieY7ahchaoCh0eeTa";
pub const NOT_ADMIN_TEST_EMAIL: &str = "krab_test@example.com";

pub static PORT_ALLOC: AtomicU16 = AtomicU16::new(18080);

pub const TEST_INTEGRATION_RS_ID: &str = "test_integration";
pub const TEST_INTEGRATION_RS_GROUP_ALL: &str = "idm_all_accounts";
pub const TEST_INTEGRATION_RS_DISPLAY: &str = "Test Integration";
pub const TEST_INTEGRATION_RS_URL: &str = "https://demo.example.com";
pub const TEST_INTEGRATION_RS_REDIRECT_URL: &str = "https://demo.example.com/oauth2/flow";
pub const TEST_INTEGRATION_STATE_VALUE: &str = "KrabzRc0ol";

pub use testkit_macros::test;
use tracing::trace;

pub fn is_free_port(port: u16) -> bool {
    TcpStream::connect(("0.0.0.0", port)).is_err()
}

// Test external behaviours of the service.
fn port_loop() -> u16 {
    let mut counter = 0;
    loop {
        let possible_port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
        if is_free_port(possible_port) {
            break possible_port;
        }
        counter += 1;
        #[allow(clippy::panic)]
        if counter >= 5 {
            tracing::error!("Unable to allocate port!");
            panic!();
        }
    }
}

pub struct AsyncTestEnvironment {
    pub rsclient: KanidmClient,
    pub http_sock_addr: SocketAddr,
    pub core_handle: CoreHandle,
    pub ldap_url: Option<Url>,
}

// allowed because the use of this function is behind a test gate
#[allow(dead_code)]
pub async fn setup_async_test(mut config: Configuration) -> AsyncTestEnvironment {
    sketching::test_init();

    let port = port_loop();

    let int_config = Box::new(IntegrationTestConfig {
        admin_user: ADMIN_TEST_USER.to_string(),
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
        idm_admin_user: IDM_ADMIN_TEST_USER.to_string(),
        idm_admin_password: IDM_ADMIN_TEST_PASSWORD.to_string(),
    });

    #[allow(clippy::expect_used)]
    let addr =
        Url::from_str(&format!("http://localhost:{port}")).expect("Failed to parse origin URL");

    let ldap_url = if config.ldapbindaddress.is_some() {
        let ldapport = port_loop();
        let ldap_sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), ldapport);
        config.ldapbindaddress = Some(ldap_sock_addr.to_string());
        Url::parse(&format!("ldap://{ldap_sock_addr}"))
            .inspect_err(|err| error!(?err, "ldap address setup"))
            .ok()
    } else {
        None
    };

    // Setup the address and origin..
    let http_sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    config.address = http_sock_addr.to_string();
    config.integration_test_config = Some(int_config);
    config.domain = "localhost".to_string();
    config.origin.clone_from(&addr);

    let core_handle = match create_server_core(config, false).await {
        Ok(val) => val,
        #[allow(clippy::panic)]
        Err(_) => panic!("failed to start server core"),
    };
    // We have to yield now to guarantee that the elements are setup.
    task::yield_now().await;

    #[allow(clippy::panic)]
    let rsclient = match KanidmClientBuilder::new()
        .address(addr.to_string())
        .enable_native_ca_roots(false)
        .no_proxy()
        .build()
    {
        Ok(val) => val,
        Err(_) => panic!("failed to build client"),
    };

    tracing::info!("Testkit server setup complete - {}", addr);

    AsyncTestEnvironment {
        rsclient,
        http_sock_addr,
        core_handle,
        ldap_url,
    }
}

pub async fn setup_account_passkey(
    rsclient: &KanidmClient,
    account_name: &str,
) -> WebauthnAuthenticator<SoftPasskey> {
    // Create an intent token for them
    let intent_token = rsclient
        .idm_person_account_credential_update_intent(account_name, Some(1234))
        .await
        .expect("Unable to setup account passkey");

    // Create a new empty session.
    let rsclient = rsclient
        .new_session()
        .expect("Unable to create new client session");

    // Exchange the intent token
    let (session_token, _status) = rsclient
        .idm_account_credential_update_exchange(intent_token.token)
        .await
        .expect("Unable to exchange credential update token");

    let _status = rsclient
        .idm_account_credential_update_status(&session_token)
        .await
        .expect("Unable to check credential update status");

    // Setup and update the passkey
    let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let status = rsclient
        .idm_account_credential_update_passkey_init(&session_token)
        .await
        .expect("Unable to init passkey update");

    let passkey_chal = match status.mfaregstate {
        CURegState::Passkey(c) => Some(c),
        _ => None,
    }
    .expect("Unable to access passkey challenge, invalid state");

    eprintln!("{}", rsclient.get_origin());
    let passkey_resp = wa
        .do_registration(rsclient.get_origin().clone(), passkey_chal)
        .expect("Failed to create soft passkey");

    let label = "Soft Passkey".to_string();

    let status = rsclient
        .idm_account_credential_update_passkey_finish(&session_token, label, passkey_resp)
        .await
        .expect("Unable to finish passkey credential");

    assert!(status.can_commit);
    assert_eq!(status.passkeys.len(), 1);

    // Commit it
    rsclient
        .idm_account_credential_update_commit(&session_token)
        .await
        .expect("Unable to commit credential update");

    // Assert it now works.
    let _ = rsclient.logout().await;

    wa
}

/// creates a user (username: `id`) and puts them into a group, creating it if need be.
pub async fn create_user(rsclient: &KanidmClient, id: &str, group_name: &str) {
    #[allow(clippy::expect_used)]
    rsclient
        .idm_person_account_create(id, id)
        .await
        .expect("Failed to create the user");

    // Create group and add to user to test read attr: member_of
    #[allow(clippy::panic)]
    if rsclient
        .idm_group_get(group_name)
        .await
        .unwrap_or_else(|_| panic!("Failed to get group {group_name}"))
        .is_none()
    {
        #[allow(clippy::panic)]
        rsclient
            .idm_group_create(group_name, None)
            .await
            .unwrap_or_else(|_| panic!("Failed to create group {group_name}"));
    }
    #[allow(clippy::panic)]
    rsclient
        .idm_group_add_members(group_name, &[id])
        .await
        .unwrap_or_else(|_| panic!("Failed to add user {id} to group {group_name}"));
}

pub async fn create_user_with_all_attrs(
    rsclient: &KanidmClient,
    id: &str,
    optional_group: Option<&str>,
) {
    let group_format = format!("{id}_group");
    let group_name = optional_group.unwrap_or(&group_format);

    create_user(rsclient, id, group_name).await;
    add_all_attrs(rsclient, id, group_name, Some(id)).await;
}

pub async fn add_all_attrs(
    rsclient: &KanidmClient,
    id: &str,
    group_name: &str,
    legalname: Option<&str>,
) {
    // Extend with posix attrs to test read attr: gidnumber and loginshell
    #[allow(clippy::expect_used)]
    rsclient
        .idm_person_account_unix_extend(id, None, Some("/bin/sh"))
        .await
        .expect("Failed to set shell to /bin/sh for user");
    #[allow(clippy::expect_used)]
    rsclient
        .idm_group_unix_extend(group_name, None)
        .await
        .expect("Failed to extend user group");

    for attr in [Attribute::SshPublicKey, Attribute::Mail].into_iter() {
        println!("Checking writable for {attr}");
        #[allow(clippy::expect_used)]
        let res = is_attr_writable(rsclient, id, attr)
            .await
            .expect("Failed to get writable status for attribute");
        assert!(res);
    }

    if let Some(legalname) = legalname {
        #[allow(clippy::expect_used)]
        let res = is_attr_writable(rsclient, legalname, Attribute::LegalName)
            .await
            .expect("Failed to get writable status for legalname field");
        assert!(res);
    }

    // Write radius credentials
    if id != "anonymous" {
        login_account(rsclient, id).await;
        #[allow(clippy::expect_used)]
        let _ = rsclient
            .idm_account_radius_credential_regenerate(id)
            .await
            .expect("Failed to regen password for user");

        #[allow(clippy::expect_used)]
        rsclient
            .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
            .await
            .expect("Failed to auth with password as admin!");
    }
}

pub async fn is_attr_writable(rsclient: &KanidmClient, id: &str, attr: Attribute) -> Option<bool> {
    println!("writing to attribute: {attr}");
    match attr {
        Attribute::RadiusSecret => Some(
            rsclient
                .idm_account_radius_credential_regenerate(id)
                .await
                .is_ok(),
        ),
        Attribute::PrimaryCredential => Some(
            rsclient
                .idm_person_account_primary_credential_set_password(id, "dsadjasiodqwjk12asdl")
                .await
                .is_ok(),
        ),
        Attribute::SshPublicKey => Some(
            rsclient
                .idm_person_account_post_ssh_pubkey(
                    id,
                    "k1",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0\
                     L1EyR30CwoP william@amethyst",
                )
                .await
                .is_ok(),
        ),
        Attribute::UnixPassword => Some(
            rsclient
                .idm_person_account_unix_cred_put(id, "dsadjasiodqwjk12asdl")
                .await
                .is_ok(),
        ),
        Attribute::LegalName => Some(
            rsclient
                .idm_person_account_set_attr(
                    id,
                    Attribute::LegalName.as_ref(),
                    &["test legal name"],
                )
                .await
                .is_ok(),
        ),
        Attribute::Mail => Some(
            rsclient
                .idm_person_account_set_attr(
                    id,
                    Attribute::Mail.as_ref(),
                    &[&format!("{id}@example.com")],
                )
                .await
                .is_ok(),
        ),
        ref entry => {
            let new_value = match entry {
                Attribute::AcpReceiverGroup => "00000000-0000-0000-0000-000000000011".to_string(),
                Attribute::AcpTargetScope => "{\"and\": [{\"eq\": [\"class\",\"access_control_profile\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}".to_string(),
                 _ => id.to_string(),
            };
            let m = ModifyList::new_list(vec![
                Modify::Purged(attr.to_string()),
                Modify::Present(attr.to_string(), new_value),
            ]);
            let f = Filter::Eq(Attribute::Name.to_string(), id.to_string());
            Some(rsclient.modify(f.clone(), m.clone()).await.is_ok())
        }
    }
}

pub async fn login_account(rsclient: &KanidmClient, id: &str) {
    #[allow(clippy::expect_used)]
    rsclient
        .idm_person_account_primary_credential_set_password(id, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to set password for user");

    let _ = rsclient.logout().await;
    let res = rsclient
        .auth_simple_password(id, NOT_ADMIN_TEST_PASSWORD)
        .await;

    // Setup privs
    println!("{id} logged in");
    assert!(res.is_ok());

    let res = rsclient
        .reauth_simple_password(NOT_ADMIN_TEST_PASSWORD)
        .await;
    println!("{id} priv granted for");
    assert!(res.is_ok());
}

// Login to the given account, but first login with default admin credentials.
// This is necessary when switching between unprivileged accounts, but adds extra calls which
// create extra debugging noise, so should be avoided when unnecessary.
pub async fn login_account_via_admin(rsclient: &KanidmClient, id: &str) {
    let _ = rsclient.logout().await;

    #[allow(clippy::expect_used)]
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to login as admin!");
    login_account(rsclient, id).await
}

pub async fn test_read_attrs(
    rsclient: &KanidmClient,
    id: &str,
    attrs: &[Attribute],
    is_readable: bool,
) {
    println!("Test read to {id}, is readable: {is_readable}");
    #[allow(clippy::expect_used)]
    let rset = rsclient
        .search(Filter::Eq(Attribute::Name.to_string(), id.to_string()))
        .await
        .expect("Can't get user from search");

    #[allow(clippy::expect_used)]
    let e = rset.first().expect("Failed to get first user from set");

    for attr in attrs.iter() {
        trace!("Reading {}", attr);
        #[allow(clippy::unwrap_used)]
        let is_ok = match *attr {
            Attribute::RadiusSecret => rsclient
                .idm_account_radius_credential_get(id)
                .await
                .unwrap()
                .is_some(),
            _ => e.attrs.contains_key(attr.as_str()),
        };
        trace!("is_ok: {}, is_readable: {}", is_ok, is_readable);
        assert_eq!(is_ok, is_readable)
    }
}

pub async fn test_write_attrs(
    rsclient: &KanidmClient,
    id: &str,
    attrs: &[Attribute],
    is_writeable: bool,
) {
    println!("Test write to {id}, is writeable: {is_writeable}");
    for attr in attrs.iter() {
        println!("Writing to {attr} - ex {is_writeable}");
        #[allow(clippy::unwrap_used)]
        let is_ok = is_attr_writable(rsclient, id, attr.clone()).await.unwrap();
        assert_eq!(is_ok, is_writeable)
    }
}

pub async fn test_modify_group(
    rsclient: &KanidmClient,
    group_names: &[&str],
    can_be_modified: bool,
) {
    // need user test created to be added as test part
    for group in group_names.iter() {
        println!("Testing group: {group}");
        for attr in [Attribute::Description, Attribute::Name].into_iter() {
            #[allow(clippy::unwrap_used)]
            let is_writable = is_attr_writable(rsclient, group, attr.clone())
                .await
                .unwrap();
            dbg!(group, attr, is_writable, can_be_modified);
            assert_eq!(is_writable, can_be_modified)
        }
        assert!(
            rsclient
                .idm_group_add_members(group, &[NOT_ADMIN_TEST_USERNAME])
                .await
                .is_ok()
                == can_be_modified
        );
    }
}

/// Logs in with the admin user and puts them in idm_admins so they can do admin things
pub async fn login_put_admin_idm_admins(rsclient: &KanidmClient) {
    #[allow(clippy::expect_used)]
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin!");

    #[allow(clippy::expect_used)]
    rsclient
        .idm_group_add_members(NAME_SYSTEM_ADMINS, &[ADMIN_TEST_USER])
        .await
        .expect("Failed to add admin user to idm_admins")
}

#[macro_export]
macro_rules! assert_no_cache {
    ($response:expr) => {{
        // Check we have correct nocache headers.
        let cache_header: &str = $response
            .headers()
            .get(kanidm_client::http::header::CACHE_CONTROL)
            .expect("missing cache-control header")
            .to_str()
            .expect("invalid cache-control header");

        assert!(cache_header.contains("no-store"));
        assert!(cache_header.contains("max-age=0"));

        let pragma_header: &str = $response
            .headers()
            .get("pragma")
            .expect("missing cache-control header")
            .to_str()
            .expect("invalid cache-control header");

        assert!(pragma_header.contains("no-cache"));
    }};
}
