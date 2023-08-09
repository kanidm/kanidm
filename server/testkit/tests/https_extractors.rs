use kanidm_client::{KanidmClient, APPLICATION_JSON};
use kanidm_proto::v1::{AuthIssueSession, AuthRequest, AuthStep};
use reqwest::header::CONTENT_TYPE;

#[kanidmd_testkit::test(trust_x_forward_for = false)]
async fn dont_trust_xff_send_header(rsclient: KanidmClient) {
    let addr = rsclient.get_url();
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let auth_init = AuthRequest {
        step: AuthStep::Init2 {
            username: "anonymous".to_string(),
            issue: AuthIssueSession::Token,
        },
    };

    let response = client
        .post([&addr, "/v1/auth"].concat())
        .header(
            "X-Forwarded-For",
            "An invalid header that will get through!!!",
        )
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(serde_json::to_string(&auth_init).unwrap())
        .send()
        .await
        .unwrap();
    assert!(dbg!(response).status() == 200);
}

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn dont_trust_xff_dont_send_header(rsclient: KanidmClient) {
    // Now login as anonymous
    let res = rsclient.auth_anonymous().await;
    assert!(res.is_ok());

    // Now do a whoami.
    let e = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned");
    assert!(e.attrs.get("spn") == Some(&vec!["anonymous@localhost".to_string()]));
}

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_send_header(rsclient: KanidmClient) {
    let addr = rsclient.get_url();
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let auth_init = AuthRequest {
        step: AuthStep::Init2 {
            username: "anonymous".to_string(),
            issue: AuthIssueSession::Token,
        },
    };

    let response = client
        .post([&addr, "/v1/auth"].concat())
        .header(
            "X-Forwarded-For",
            "a VERY much invalid header that WON'T get through!!",
        )
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(serde_json::to_string(&auth_init).unwrap())
        .send()
        .await
        .unwrap();
    assert!(dbg!(response).status() == 400);
}

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_dont_send_header(rsclient: KanidmClient) {
    // Now login as anonymous
    let res = rsclient.auth_anonymous().await;
    assert!(res.is_ok());

    // Now do a whoami.
    let e = rsclient
        .whoami()
        .await
        .expect("Unable to call whoami")
        .expect("No entry matching self returned");
    assert!(e.attrs.get("spn") == Some(&vec!["anonymous@localhost".to_string()]));
}
