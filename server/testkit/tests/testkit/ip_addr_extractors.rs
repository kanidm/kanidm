use cidr::IpCidr;
use kanidm_client::KanidmClient;
use kanidm_proto::constants::X_FORWARDED_FOR;
use kanidmd_core::config::HttpAddressInfo;
use kanidmd_testkit::AsyncTestEnvironment;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use tracing::error;

const DEFAULT_IP_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// =====================================================
// *test where we don't trust the x-forwarded-for header

#[kanidmd_testkit::test(http_client_address_info = HttpAddressInfo::None)]
async fn dont_trust_xff_send_header(rsclient: &KanidmClient) {
    let client = rsclient.client();

    // Send an invalid header to x forwdr for
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(X_FORWARDED_FOR, "a.b.c.d")
        .send()
        .await
        .unwrap();

    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as IpAddr");

    assert_eq!(ip_res, DEFAULT_IP_ADDRESS);

    // Send a valid header for xforward for, but we don't trust it.
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(X_FORWARDED_FOR, "203.0.113.195")
        .send()
        .await
        .unwrap();

    let ip_res: IpAddr = res
        .json()
        .await
        .expect("Failed to parse response as IpAddr");

    assert_eq!(ip_res, DEFAULT_IP_ADDRESS);
}

// =====================================================
// *test where we do trust the x-forwarded-for header

#[kanidmd_testkit::test(http_client_address_info = HttpAddressInfo::XForwardFor ( [IpCidr::from(DEFAULT_IP_ADDRESS)].into() ))]
async fn trust_xff_address_set(rsclient: &KanidmClient) {
    inner_test_trust_xff(rsclient).await;
}

#[kanidmd_testkit::test(http_client_address_info = HttpAddressInfo::XForwardForAllSourcesTrusted)]
async fn trust_xff_all_addresses_trusted(rsclient: &KanidmClient) {
    inner_test_trust_xff(rsclient).await;
}

async fn inner_test_trust_xff(rsclient: &KanidmClient) {
    let client = rsclient.client();

    // An invalid address.
    let res = client
        .get(rsclient.make_url("/v1/debug/ipinfo"))
        .header(X_FORWARDED_FOR, "a.b.c.d")
        .send()
        .await
        .unwrap();

    // Header was invalid
    assert_eq!(res.status(), 400);

    // An invalid address - what follows doesn't matter, even if it was valid. We only
    // care about the left most address anyway.
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

    // A valid ipv6 address was provided.
    let ip_addr = "2001:db8:85a3:8d3:1319:8a2e:370:7348";

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

    // A valid ipv4 address was provided.
    let ip_addr = "203.0.113.195";

    let client = rsclient.client();

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

    // A valid ipv4 address in the leftmost field.
    let first_ip_addr = "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348";

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

    // A valid ipv6 address in the left most field.
    let second_ip_addr = "2001:db8:85a3:8d3:1319:8a2e:370:7348, 198.51.100.178, 203.0.113.195";

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

    // If no header is sent, then the connection IP is used.
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

// =====================================================
// *test where we do trust the PROXY protocol header
//
// NOTE: This is MUCH HARDER TO TEST because we can't just stuff this address
// in front of a reqwest call. We have to open raw connections and write the
// requests to them.
//
// As a result, we are pretty much forced to manually dump binary headers and then
// manually craft get reqs, followed by parsing them.

#[derive(Debug, PartialEq)]
enum ProxyV2Error {
    TcpStream,
    TcpWrite,
    TornWrite,
    HttpHandshake,
    HttpRequestBuild,
    HttpRequest,
    HttpBadRequest,
}

async fn proxy_v2_make_request(
    http_sock_addr: SocketAddr,
    hdr: &[u8],
) -> Result<IpAddr, ProxyV2Error> {
    use http_body_util::BodyExt;
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Request;
    use hyper_util::rt::TokioIo;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpStream;

    let url = format!("http://{}/v1/debug/ipinfo", http_sock_addr)
        .as_str()
        .parse::<hyper::Uri>()
        .unwrap();

    let mut stream = TcpStream::connect(http_sock_addr).await.map_err(|err| {
        error!(?err);
        ProxyV2Error::TcpStream
    })?;

    // Write the proxyv2 header
    let nbytes = stream.write(hdr).await.map_err(|err| {
        error!(?err);
        ProxyV2Error::TcpWrite
    })?;

    if nbytes != hdr.len() {
        return Err(ProxyV2Error::TornWrite);
    }

    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|err| {
            error!(?err);
            ProxyV2Error::HttpHandshake
        })?;

    // Spawn a task to poll the connection, driving the HTTP state
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let authority = url.authority().unwrap().clone();

    // Create an HTTP request with an empty body and a HOST header
    let req = Request::builder()
        .uri(url)
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())
        .map_err(|err| {
            error!(?err);
            ProxyV2Error::HttpRequestBuild
        })?;

    // Await the response...
    let mut res = sender.send_request(req).await.map_err(|err| {
        error!(?err);
        ProxyV2Error::HttpRequest
    })?;

    println!("Response status: {}", res.status());

    if res.status() != 200 {
        return Err(ProxyV2Error::HttpBadRequest);
    }

    let mut data: Vec<u8> = Vec::new();

    while let Some(next) = res.frame().await {
        let frame = next.unwrap();
        if let Some(chunk) = frame.data_ref() {
            data.write_all(chunk).await.unwrap();
        }
    }

    tracing::info!(?data);
    let ip_res: IpAddr = serde_json::from_slice(&data).unwrap();
    tracing::info!(?ip_res);

    Ok(ip_res)
}

#[kanidmd_testkit::test(with_test_env = true, http_client_address_info = HttpAddressInfo::ProxyV2 ( [IpCidr::from(DEFAULT_IP_ADDRESS)].into() ))]
async fn trust_proxy_v2_address_set(test_env: &AsyncTestEnvironment) {
    // Send with no header - with proxy v2, a header is ALWAYS required
    let proxy_hdr: [u8; 0] = [];

    let res = proxy_v2_make_request(test_env.http_sock_addr, &proxy_hdr)
        .await
        .unwrap_err();

    // Can't send http request because proxy wasn't sent.
    assert_eq!(res, ProxyV2Error::HttpRequest);

    // Send with a valid header
    let proxy_hdr =
        hex::decode("0d0a0d0a000d0a515549540a2111000cac180c76ac180b8fcdcb027d").unwrap();

    let res = proxy_v2_make_request(test_env.http_sock_addr, &proxy_hdr)
        .await
        .unwrap();

    // The header was valid
    assert_eq!(res, IpAddr::V4(Ipv4Addr::new(172, 24, 12, 118)));
}

#[kanidmd_testkit::test(with_test_env = true, http_client_address_info = HttpAddressInfo::ProxyV2 ( [ IpCidr::from(Ipv4Addr::new(10, 0, 0, 1)) ].into() ))]
async fn trust_proxy_v2_untrusted(test_env: &AsyncTestEnvironment) {
    // Send with a valid header, but we aren't a trusted source.
    let proxy_hdr =
        hex::decode("0d0a0d0a000d0a515549540a2111000cac180c76ac180b8fcdcb027d").unwrap();

    let res = proxy_v2_make_request(test_env.http_sock_addr, &proxy_hdr)
        .await
        .unwrap_err();

    // Can't send http request because we aren't trusted to send it, so this
    // ends up falling into a http request that is REJECTED.
    assert_eq!(res, ProxyV2Error::HttpBadRequest);
}
