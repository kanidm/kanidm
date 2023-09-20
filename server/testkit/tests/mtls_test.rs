use kanidmd_testkit::{is_free_port, PORT_ALLOC};
use std::sync::atomic::Ordering;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time;
use tracing::{error, trace};

use openssl::asn1;
use openssl::bn;
use openssl::ec;
use openssl::hash;
use openssl::nid::Nid;
use openssl::pkey;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod};
use openssl::ssl::{SslConnector, SslVerifyMode};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509;
use tokio_openssl::SslStream;

use openssl::error::ErrorStack as OpenSSLError;

/// Gets an [EcGroup] for P-256
pub fn get_group() -> Result<ec::EcGroup, OpenSSLError> {
    ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
}

fn build_self_signed_client_server() -> Result<(pkey::PKey<pkey::Private>, X509), OpenSSLError> {
    let ecgroup = get_group()?;
    let eckey = ec::EcKey::generate(&ecgroup)?;
    let ca_key = pkey::PKey::from_ec_key(eckey)?;
    let mut x509_name = X509NameBuilder::new()?;

    x509_name.append_entry_by_text("C", "AU")?;
    x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Webauthn Authenticator RS")?;
    x509_name.append_entry_by_text("CN", "Dynamic Softtoken CA")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    // Yes, 2 actually means 3 here ...
    cert_builder.set_version(2)?;

    let serial_number = bn::BigNum::from_u32(1).and_then(|serial| serial.to_asn1_integer())?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;

    let not_before = asn1::Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = asn1::Asn1Time::days_from_now(1)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.set_pubkey(&ca_key)?;

    cert_builder.sign(&ca_key, hash::MessageDigest::sha256())?;
    let ca_cert = cert_builder.build();

    Ok((ca_key, ca_cert))
}

#[tokio::test]
async fn test_mtls_basic_auth() {
    sketching::test_init();

    let mut counter = 0;
    let port = loop {
        let possible_port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
        if is_free_port(possible_port) {
            break possible_port;
        }
        counter += 1;
        #[allow(clippy::panic)]
        if counter >= 5 {
            error!("Unable to allocate port!");
            panic!();
        }
    };

    trace!("{:?}", port);

    // First we need the two certificates.
    let (client_key, client_cert) = build_self_signed_client_server().unwrap();

    let (server_key, server_cert) = build_self_signed_client_server().unwrap();
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port);

    let listener = TcpListener::bind(&server_addr)
        .await
        .expect("Failed to bind");

    // Setup the TLS parameters.
    let (tx, mut rx) = oneshot::channel();

    let mut ssl_builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).unwrap();
    ssl_builder.set_certificate(&server_cert).unwrap();
    ssl_builder.set_private_key(&server_key).unwrap();
    ssl_builder.check_private_key().unwrap();
    let tls_parms = ssl_builder.build();

    // Start the server in a task.
    // The server is designed to stop/die as soon as a single connection has been made.
    let handle = tokio::spawn(async move {
        // This is our safety net.
        let sleep = time::sleep(Duration::from_secs(15));
        tokio::pin!(sleep);

        trace!("Started listener");
        tokio::select! {
            Ok((tcpstream, client_socket_addr)) = listener.accept() => {
                let mut tlsstream = match Ssl::new(tls_parms.context())
                    .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
                {
                    Ok(ta) => ta,
                    Err(e) => {
                        error!("LDAP TLS setup error, continuing -> {:?}", e);
                        return false;
                    }
                };

                if let Err(e) = SslStream::accept(Pin::new(&mut tlsstream)).await {
                    error!("LDAP TLS accept error, continuing -> {:?}", e);
                    return false;
                };

                trace!("Got connection. {:?}", client_socket_addr);

                true
            }
            Ok(()) = &mut rx => {
                trace!("stopping listener");
                false
            }
            _ = &mut sleep => {
                error!("timeout");
                false
            }
            else => {
                trace!("error condition in accept");
                false
            }
        }
    });

    // Create the client and connect. We do this inline to be sensitive to errors.
    let tcpclient = TcpStream::connect(server_addr).await.unwrap();
    trace!("connection established");

    let mut ssl_builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
    ssl_builder.set_certificate(&client_cert).unwrap();
    ssl_builder.set_private_key(&client_key).unwrap();
    ssl_builder.check_private_key().unwrap();
    ssl_builder.set_verify(SslVerifyMode::NONE);
    let tls_parms = ssl_builder.build();
    let mut tlsstream = Ssl::new(tls_parms.context())
        .and_then(|tls_obj| SslStream::new(tls_obj, tcpclient))
        .unwrap();

    SslStream::connect(Pin::new(&mut tlsstream)).await.unwrap();

    trace!("Waiting on listener ...");
    let result = handle.await.expect("Failed to stop task.");

    // If this isn't true, it means something failed in the server accept process.
    assert!(result);
}
