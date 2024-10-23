use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use kanidm_client::KanidmClient;
use kanidm_proto::constants::X_FORWARDED_FOR;

const DEFAULT_IP_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// *test where we don't trust the x-forwarded-for header

#[kanidmd_testkit::test(trust_x_forward_for = false)]
async fn dont_trust_xff_send_header(rsclient: KanidmClient) {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(
            X_FORWARDED_FOR,
            "An invalid header that will get through!!!",
        )
        .send()
        .await
        .unwrap();
    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as IpAddr");

    assert_eq!(ip_res, DEFAULT_IP_ADDRESS);
}

#[kanidmd_testkit::test(trust_x_forward_for = false)]
async fn dont_trust_xff_dont_send_header(rsclient: KanidmClient) {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(
            X_FORWARDED_FOR,
            "An invalid header that will get through!!!",
        )
        .send()
        .await
        .unwrap();
    let body = res.bytes().await.unwrap();
    let ip_res: IpAddr = serde_json::from_slice(&body).unwrap_or_else(|op| {
        panic!(
            "Failed to parse response as IpAddr: {:?} body: {:?}",
            op, body,
        )
    });
    eprintln!("Body: {:?}", body);
    assert_eq!(ip_res, DEFAULT_IP_ADDRESS);
}

// *test where we trust the x-forwarded-for header

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_send_invalid_header_single_value(rsclient: KanidmClient) {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(
            X_FORWARDED_FOR,
            "An invalid header that will get through!!!",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

// TODO: Right now we reject the request only if the leftmost address is invalid. In the future that could change so we could also have a test
// with a valid leftmost address and an invalid address later in the list. Right now it wouldn't work.
//
#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_send_invalid_header_multiple_values(rsclient: KanidmClient) {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(
            X_FORWARDED_FOR,
            "203.0.113.195_noooo_my_ip_address, 2001:db8:85a3:8d3:1319:8a2e:370:7348",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_send_valid_header_single_ipv4_address(rsclient: KanidmClient) {
    let ip_addr = "2001:db8:85a3:8d3:1319:8a2e:370:7348";

    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(X_FORWARDED_FOR, ip_addr)
        .send()
        .await
        .unwrap();
    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as Vec<IpAddr>");

    assert_eq!(ip_res, IpAddr::from_str(ip_addr).unwrap());
}

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_send_valid_header_single_ipv6_address(rsclient: KanidmClient) {
    let ip_addr = "203.0.113.195";

    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(X_FORWARDED_FOR, ip_addr)
        .send()
        .await
        .unwrap();
    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as Vec<IpAddr>");

    assert_eq!(ip_res, IpAddr::from_str(ip_addr).unwrap());
}

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_send_valid_header_multiple_address(rsclient: KanidmClient) {
    let first_ip_addr = "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348";

    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(X_FORWARDED_FOR, first_ip_addr)
        .send()
        .await
        .unwrap();
    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as Vec<IpAddr>");

    assert_eq!(
        ip_res,
        IpAddr::from_str(first_ip_addr.split(",").collect::<Vec<&str>>()[0]).unwrap()
    );

    let second_ip_addr = "2001:db8:85a3:8d3:1319:8a2e:370:7348, 198.51.100.178, 203.0.113.195";

    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(X_FORWARDED_FOR, second_ip_addr)
        .send()
        .await
        .unwrap();
    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as Vec<IpAddr>");

    assert_eq!(
        ip_res,
        IpAddr::from_str(second_ip_addr.split(",").collect::<Vec<&str>>()[0]).unwrap()
    );
}

#[kanidmd_testkit::test(trust_x_forward_for = true)]
async fn trust_xff_dont_send_header(rsclient: KanidmClient) {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .send()
        .await
        .unwrap();
    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as Vec<IpAddr>");

    assert_eq!(ip_res, DEFAULT_IP_ADDRESS);
}
