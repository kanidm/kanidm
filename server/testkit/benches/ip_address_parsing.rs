#[test]
fn bench_ip_address_parsing() {
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::time::Instant;

    let ip_input_some = Some("1.2.3.4:1234");
    let test_val = Some(IpAddr::from_str("1.2.3.4").unwrap());

    let iterations = 10000000u128;

    // test the split method
    let split_start = Instant::now();
    for _ in 0..iterations {
        let res: Option<IpAddr> = ip_input_some
            .map(|addr| addr.split(':').next().unwrap_or(addr))
            .and_then(|ip| ip.parse::<IpAddr>().ok());
        assert_eq!(test_val, res);
    }
    let split_end = Instant::now();

    // test the socket parsing method
    let socket_start = Instant::now();
    for _ in 0..iterations {
        let res: Option<IpAddr> = ip_input_some
            .and_then(|add_str| add_str.parse().ok())
            .map(|s_ad: SocketAddr| s_ad.ip());
        assert_eq!(test_val, res);
    }

    let socket_end = Instant::now();

    let split_time = split_end.duration_since(split_start);
    let socket_time = socket_end.duration_since(socket_start);
    println!(
        "Split time: {:?}, {}ns/iteration",
        split_time,
        split_time.as_nanos() / iterations
    );
    println!(
        "Socket time: {:?}, {}ns/iteration",
        socket_time,
        socket_time.as_nanos() / iterations
    );
}
