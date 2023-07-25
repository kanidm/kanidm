use core::result::Result::Err;
use kanidm_client::KanidmClient;
use kanidm_proto::{
    internal::{IdentifyUserRequest, IdentifyUserResponse},
    v1::Entry,
};

use kanidmd_testkit::ADMIN_TEST_PASSWORD;
use reqwest::StatusCode;

static UNIVERSAL_PW: &'static str = "eicieY7ahchaoCh0eeTa";
static UNIVERSAL_PW_HASH: &'static str =
    "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=";

static USER_A_NAME: &'static str = "valid_user_a";

static USER_B_NAME: &'static str = "valid_user_b";

// TEST ON ERROR OUTCOMES
// These tests check that invalid requests return the expected error

#[kanidmd_testkit::test]
async fn test_not_authenticated(rsclient: KanidmClient) {
    // basically here we try a bit of all the possible combinations while unauthenticated to check it's not working
    setup_server(&rsclient).await;
    create_user(&rsclient, USER_A_NAME).await;
    let _ = rsclient.logout().await;
    let res = rsclient
        .idm_person_identify_user(USER_A_NAME, IdentifyUserRequest::Start)
        .await;
    assert!(
        matches!(res, Err(err) if matches!(err, kanidm_client::ClientError::Http(reqwest::StatusCode::UNAUTHORIZED, ..)))
    );

    let res = rsclient
        .idm_person_identify_user(USER_A_NAME, IdentifyUserRequest::DisplayCode)
        .await;
    assert!(
        matches!(res, Err(err) if matches!(err, kanidm_client::ClientError::Http(reqwest::StatusCode::UNAUTHORIZED, ..)))
    );
    let res = rsclient
        .idm_person_identify_user(
            USER_A_NAME,
            IdentifyUserRequest::SubmitCode { other_totp: 123456 },
        )
        .await;

    assert!(
        matches!(res, Err(err) if matches!(err, kanidm_client::ClientError::Http(reqwest::StatusCode::UNAUTHORIZED, ..)))
    );
}

#[kanidmd_testkit::test]
async fn test_non_existing_user_id(rsclient: KanidmClient) {
    setup_server(&rsclient).await;
    create_user(&rsclient, USER_A_NAME).await;
    create_user(&rsclient, USER_B_NAME).await;
    let non_existing_user = "non_existing_user";
    login_with_user(&rsclient, USER_A_NAME).await;
    let res: Result<IdentifyUserResponse, kanidm_client::ClientError> = rsclient
        .idm_person_identify_user(non_existing_user, IdentifyUserRequest::Start)
        .await;
    assert!(
        matches!(dbg!(res), Err(err) if matches!(err, kanidm_client::ClientError::Http(StatusCode::NOT_FOUND, Some(kanidm_proto::v1::OperationError::NoMatchingEntries), .. )))
    );

    let res = rsclient
        .idm_person_identify_user(non_existing_user, IdentifyUserRequest::DisplayCode)
        .await;

    assert!(
        matches!(dbg!(res), Err(err) if matches!(err, kanidm_client::ClientError::Http(StatusCode::NOT_FOUND, Some(kanidm_proto::v1::OperationError::NoMatchingEntries), .. )))
    );

    let res = rsclient
        .idm_person_identify_user(
            non_existing_user,
            IdentifyUserRequest::SubmitCode { other_totp: 123456 },
        )
        .await;

    assert!(
        matches!(dbg!(res), Err(err) if matches!(err, kanidm_client::ClientError::Http(StatusCode::NOT_FOUND, Some(kanidm_proto::v1::OperationError::NoMatchingEntries), .. )))
    );
}

// TEST ON SPECIFIC API INPUT
// These tests check that given a specific input we get the expected response.
// WE DON'T CHECK THE CONTENT OF THE RESPONSE, just that it's the expected one.
// The api tests from here on should never return any error, as all the
// error cases have already been tested in the previous section!
// Each tests is named like `test_{api input}_response_{expected api output}_or_{expected api output}`
#[kanidmd_testkit::test]
async fn test_start_response_identity_verification_available(rsclient: KanidmClient) {
    setup_server(&rsclient).await;
    create_user(&rsclient, USER_A_NAME).await;
    login_with_user(&rsclient, USER_A_NAME).await;

    let response = rsclient
        .idm_person_identify_user(USER_A_NAME, IdentifyUserRequest::Start)
        .await;

    assert!(response.is_ok());
    // since we sent our own identifier here it should just tell us that we that we can use the feature
    assert_eq!(
        response.unwrap(),
        IdentifyUserResponse::IdentityVerificationAvailable
    )
}
// this function tests both possible POSITIVE outcomes if we start from
// `Start`, that is WaitForCode or ProvideCode
#[kanidmd_testkit::test]
async fn test_start_response_wait_for_code_or_provide_code(rsclient: KanidmClient) {
    setup_server(&rsclient).await;
    let user_a_uuid = create_user(&rsclient, USER_A_NAME).await;
    let user_b_uuid = create_user(&rsclient, USER_B_NAME).await;
    login_with_user(&rsclient, USER_A_NAME).await;
    let response = rsclient
        .idm_person_identify_user(USER_B_NAME, IdentifyUserRequest::Start)
        .await;

    assert!(response.is_ok());
    // the person with the lowest uuid should get to input the other person's code first;
    dbg!(user_a_uuid.clone(), user_b_uuid.clone());

    if user_a_uuid < user_b_uuid {
        assert_eq!(response.unwrap(), IdentifyUserResponse::WaitForCode);
    } else {
        assert!(matches!(
            response.unwrap(),
            IdentifyUserResponse::ProvideCode { .. }
        ))
    }
}

#[kanidmd_testkit::test]
async fn test_provide_code_response_code_failure_or_provide_code(rsclient: KanidmClient) {
    setup_server(&rsclient).await;
    let user_a_uuid = create_user(&rsclient, USER_A_NAME).await;
    let user_b_uuid = create_user(&rsclient, USER_B_NAME).await;
    login_with_user(&rsclient, USER_A_NAME).await;
    let response = rsclient
        .idm_person_identify_user(
            USER_B_NAME,
            IdentifyUserRequest::SubmitCode { other_totp: 123456 },
        )
        .await;
    //if A is the first then either the code is correct and therefore we get a ProvideCode or it's wrong
    // and we get a CodeFailure
    if user_a_uuid < user_b_uuid {
        assert!(matches!(
            response.unwrap(),
            IdentifyUserResponse::ProvideCode { .. } | IdentifyUserResponse::CodeFailure
        ));
    } else {
        assert!(matches!(
            response.unwrap(),
            IdentifyUserResponse::Success | IdentifyUserResponse::CodeFailure
        ));
    }
}

// here we actually test the full idm flow by duplicating the server
#[kanidmd_testkit::test]
async fn test_full_identification_flow(rsclient: KanidmClient) {
    setup_server(&rsclient).await;
    let user_a_uuid = create_user(&rsclient, USER_A_NAME).await;
    let user_b_uuid = create_user(&rsclient, USER_B_NAME).await;
    //user A session
    let valid_user_a_client = rsclient;
    login_with_user(&valid_user_a_client, USER_A_NAME).await;
    //user B session
    let valid_user_b_client = valid_user_a_client.new_session().unwrap();
    login_with_user(&valid_user_b_client, USER_B_NAME).await;

    // now we have to consider the two separate cases: first we address the case a has the lowest uuid

    let (lower_user_client, lower_user_name, higher_user_client, higher_user_name) =
        if user_a_uuid < user_b_uuid {
            (
                valid_user_a_client,
                USER_A_NAME,
                valid_user_b_client,
                USER_B_NAME,
            )
        } else {
            (
                valid_user_b_client,
                USER_B_NAME,
                valid_user_a_client,
                USER_A_NAME,
            )
        };

    let lower_user_req_1 = lower_user_client
        .idm_person_identify_user(higher_user_name, IdentifyUserRequest::Start)
        .await
        .unwrap();

    let higher_user_req_1 = higher_user_client
        .idm_person_identify_user(lower_user_name, IdentifyUserRequest::Start)
        .await
        .unwrap();

    assert_eq!(lower_user_req_1, IdentifyUserResponse::WaitForCode);
    // we check that the user A got a WaitForCode

    let IdentifyUserResponse::ProvideCode { step: _, totp } = higher_user_req_1 else {
            return assert!(false);
            // we check that the user B got the code
        };
    // we now try to submit the wrong code and we check that we get CodeFailure
    // we now submit the received totp as the user A

    let lower_user_req_2_wrong = lower_user_client
        .idm_person_identify_user(
            higher_user_name,
            IdentifyUserRequest::SubmitCode {
                other_totp: totp + 1,
            },
        )
        .await
        .unwrap();

    assert_eq!(lower_user_req_2_wrong, IdentifyUserResponse::CodeFailure);
    // now we do it using the right totp
    let lower_user_req_2_right = lower_user_client
        .idm_person_identify_user(
            higher_user_name,
            IdentifyUserRequest::SubmitCode { other_totp: totp },
        )
        .await
        .unwrap();
    // if the totp was correct we must get a ProvideCode
    let IdentifyUserResponse::ProvideCode { step: _, totp } = lower_user_req_2_right else {
                return assert!(false)
        };
    // we now try to do the same thing with user B: we first submit the wrong code expecting CodeFailure,
    // and then we submit the right one expecting Success

    let higher_user_req_2_wrong = higher_user_client
        .idm_person_identify_user(
            lower_user_name,
            IdentifyUserRequest::SubmitCode {
                other_totp: totp + 1,
            },
        )
        .await
        .unwrap();

    assert_eq!(higher_user_req_2_wrong, IdentifyUserResponse::CodeFailure);
    // now we do it using the right totp
    let higher_user_req_2_right = higher_user_client
        .idm_person_identify_user(
            lower_user_name,
            IdentifyUserRequest::SubmitCode { other_totp: totp },
        )
        .await
        .unwrap();
    // since user B has already provided their code this is their last action and they must get a Success if
    // the provided code is correct
    assert_eq!(higher_user_req_2_right, IdentifyUserResponse::Success);
}

async fn setup_server(rsclient: &KanidmClient) {
    // basically this function logs in
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // To enable the admin to actually make some of these changes, we have
    // to make them a people admin. NOT recommended in production!
    rsclient
        .idm_group_add_members("idm_people_account_password_import_priv", &["admin"])
        .await
        .unwrap();

    rsclient
        .idm_group_add_members("idm_people_manage_priv", &["admin"])
        .await
        .unwrap();

    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .await
        .unwrap();
}

async fn create_user(rsclient: &KanidmClient, user: &str) -> String {
    let e: Entry = serde_json::from_str(&format!(
        r#"{{
            "attrs": {{
                "class": ["account", "person", "object"],
                "name": ["{}"],
                "displayname": ["dx{}"]
            }}
        }}"#,
        user, user
    ))
    .unwrap();
    let res = rsclient.create(vec![e.clone()]).await;

    assert!(res.is_ok());
    rsclient
        .idm_person_account_primary_credential_import_password(user, UNIVERSAL_PW_HASH)
        .await
        .unwrap();
    let r = rsclient
        .idm_person_account_get_attr(user, "uuid")
        .await
        .unwrap();
    r.unwrap().first().unwrap().to_owned()
}

async fn login_with_user(rsclient: &KanidmClient, id: &str) {
    let _ = rsclient.logout().await;

    let res = rsclient.auth_simple_password(id, UNIVERSAL_PW).await;
    assert!(res.is_ok());
}
