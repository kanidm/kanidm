use crate::config::TcpAddressInfo;
use haproxy_protocol::{ProxyHdrV1, ProxyHdrV2, RemoteAddress};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{net::TcpStream, time::timeout};

pub(crate) async fn process_client_addr(
    stream: TcpStream,
    connection_addr: SocketAddr,
    time_limit: Duration,
    trusted_tcp_info_ips: Arc<TcpAddressInfo>,
) -> Result<(TcpStream, SocketAddr), std::io::Error> {
    let canonical_conn_addr = connection_addr.ip().to_canonical();

    let hdr_result = match trusted_tcp_info_ips.as_ref() {
        TcpAddressInfo::ProxyV2(trusted)
            if trusted
                .iter()
                .any(|ip_cidr| ip_cidr.contains(&canonical_conn_addr)) =>
        {
            timeout(time_limit, ProxyHdrV2::parse_from_read(stream))
                .await
                .map(|ok_result| ok_result.map(|(stream, hdr)| (stream, hdr.to_remote_addr())))
        }
        TcpAddressInfo::ProxyV1(trusted)
            if trusted
                .iter()
                .any(|ip_cidr| ip_cidr.contains(&canonical_conn_addr)) =>
        {
            timeout(time_limit, ProxyHdrV1::parse_from_read(stream))
                .await
                .map(|ok_result| ok_result.map(|(stream, hdr)| (stream, hdr.to_remote_addr())))
        }
        TcpAddressInfo::ProxyV2(_) | TcpAddressInfo::ProxyV1(_) | TcpAddressInfo::None => {
            return Ok((stream, connection_addr))
        }
    };

    match hdr_result {
        Ok(Ok((stream, remote_addr))) => {
            let remote_socket_addr = match remote_addr {
                RemoteAddress::Local => {
                    debug!("PROXY protocol liveness check - will not contain client data");
                    // This is a check from the proxy, so just use the connection address.
                    connection_addr
                }
                RemoteAddress::TcpV4 { src, dst: _ } => SocketAddr::from(src),
                RemoteAddress::TcpV6 { src, dst: _ } => SocketAddr::from(src),
                remote_addr => {
                    error!(?remote_addr, "remote address in proxy header is invalid");
                    return Err(std::io::Error::from(ErrorKind::ConnectionAborted));
                }
            };

            Ok((stream, remote_socket_addr))
        }
        Ok(Err(err)) => {
            error!(?connection_addr, ?err, "Unable to process proxy header");
            return Err(std::io::Error::from(ErrorKind::ConnectionAborted));
        }
        Err(_) => {
            error!(?connection_addr, "Timeout receiving proxy header");
            return Err(std::io::Error::from(ErrorKind::TimedOut));
        }
    }
}
