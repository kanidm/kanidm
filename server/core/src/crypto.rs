//! This module contains cryptographic setup code, a long with what policy
//! and ciphers we accept.

use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::rsa::Rsa;
use openssl::x509::{
    extension::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectAlternativeName, SubjectKeyIdentifier,
    },
    X509NameBuilder, X509ReqBuilder, X509,
};
use openssl::{asn1, bn, hash, pkey};

// use sketching::*;
use crate::config::TlsConfiguration;
use crypto_glue::{
    pkcs8::PrivateKeyInfo, rsa::RS256PrivateKey, traits::{PublicKeyParts, DecodeDer, Pkcs1DecodeRsaPrivateKey}, x509::oiddb::rfc5912,
};
use sec1::EcPrivateKey;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, CertificateRevocationListDer, PrivateKeyDer},
    server::{ServerConfig, WebPkiClientVerifier},
    RootCertStore,
};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

const CA_VALID_DAYS: u32 = 30;
const CERT_VALID_DAYS: u32 = 5;

// Basing minimums off https://www.keylength.com setting "year" to 2030 - tested as at 2023-09-25
//
// |Method           |Date     |Symmetric| FM      |DL Key| DL Group|Elliptic Curve|Hash|
// |   ---           |   ---   |   ---   |   ---   | ---  |   ---   |  ---         | ---|
// |Lenstra / Verheul|2030     |  93     |2493^2016|165   | 2493    |  176         | 186|
// |Lenstra Updated  |2030     |  88     |1698^2063|176   | 1698    |  176         | 176|
// |ECRYPT           |2029-2068|  256    |15360    |512   | 15360   |  512         | 512|
// |NIST             |2019-2030|  112    |2048     |224   | 2048    |  224         | 224|
// |ANSSI            |> 2030   |  128    |3072     |200   | 3072    |  256         | 256|
// |NSA              |-        |  256    |3072     |-     | -       |  384         | 384|
// |RFC3766          |-        |  -      |   -     | -    |   -     |   -          |  - |
// |BSI              |-        |  -      |   -     | -    |   -     |   -          |  - |
// DL - Discrete Logarithm
// FM - Factoring Modulus

const RSA_MIN_KEY_SIZE_BITS: u64 = 2048;
const EC_MIN_KEY_SIZE_BITS: u64 = 224;

/// returns a signing function that meets a sensible minimum
fn get_signing_func() -> hash::MessageDigest {
    hash::MessageDigest::sha256()
}

/// Ensure we're enforcing safe minimums for TLS keys
pub fn check_privkey_minimums(privkey: &PrivateKeyDer<'_>) -> Result<(), String> {
    match privkey {
        PrivateKeyDer::Pkcs8(pkcs8_der) => {
            let private_key_info = PrivateKeyInfo::try_from(pkcs8_der.secret_pkcs8_der())
                .map_err(|_err| "Invalid pkcs8 der".to_string())?;

            let oids = private_key_info
                .algorithm
                .oids()
                .map_err(|_err| "Invalid pkcs8 key oids".to_string())?;

            match oids {
                (rfc5912::ID_EC_PUBLIC_KEY, Some(rfc5912::SECP_256_R_1)) => {
                    debug!("The EC private key size is: 256 bits, that's OK!");
                    Ok(())
                }
                (rfc5912::ID_EC_PUBLIC_KEY, Some(rfc5912::SECP_384_R_1)) => {
                    debug!("The EC private key size is: 384 bits, that's OK!");
                    Ok(())
                }
                (rfc5912::RSA_ENCRYPTION, None) => {
                    let priv_key = RS256PrivateKey::try_from(private_key_info)
                        .map_err(|_err| "Invalid rsa key".to_string())?;

                    let priv_key_bits = priv_key.size() * 8;

                    if priv_key_bits < RSA_MIN_KEY_SIZE_BITS as usize {
                        Err(format!(
                            "TLS RSA key is less than {RSA_MIN_KEY_SIZE_BITS} bits!"
                        ))
                    } else {
                        debug!(
                            "The RSA private key size is: {} bits, that's OK!",
                            priv_key_bits
                        );
                        Ok(())
                    }
                }
                _ => Err("TLS Private Key Oids not understood".into()),
            }
        }
        PrivateKeyDer::Sec1(sec1_der) => {
            // ECDSA only
            let priv_key = EcPrivateKey::from_der(sec1_der.secret_sec1_der())
                .map_err(|_err| "Invalid sec1 der".to_string())?;

            match priv_key.parameters
                .and_then(|params| params.named_curve())
            {
                Some(rfc5912::SECP_256_R_1) => {
                    debug!("The EC private key size is: 256 bits, that's OK!");
                    Ok(())
                }
                Some(rfc5912::SECP_384_R_1) => {
                    debug!("The EC private key size is: 384 bits, that's OK!");
                    Ok(())
                }
                Some(_) => Err("TLS Private Key Oids not understood".into()),
                None => Err("TLS Private Key has no oids".into()),
            }
        }
        PrivateKeyDer::Pkcs1(pkcs1_der) => {
            // RSA only
            let priv_key = RS256PrivateKey::from_pkcs1_der(pkcs1_der.secret_pkcs1_der())
                .map_err(|_err| "Invalid pkcs1 der".to_string())?;

            let priv_key_bits = priv_key.size() * 8;

            if priv_key_bits < RSA_MIN_KEY_SIZE_BITS as usize {
                Err(format!(
                    "TLS RSA key is less than {RSA_MIN_KEY_SIZE_BITS} bits!"
                ))
            } else {
                debug!(
                    "The RSA private key size is: {} bits, that's OK!",
                    priv_key_bits
                );
                Ok(())
            }
        }
        _ => Err("TLS Private Key Format not understood".into()),
    }
}

/// From the server configuration, generate an OpenSSL acceptor that we can use
/// to build our sockets for HTTPS/LDAPS.
pub fn setup_tls(
    tls_config: &Option<TlsConfiguration>,
) -> Result<Option<TlsAcceptor>, std::io::Error> {
    let Some(tls_param) = tls_config.as_ref() else {
        return Ok(None);
    };

    let cert_iter = CertificateDer::pem_file_iter(&tls_param.chain)
        .map_err(|err| std::io::Error::other(format!("Failed to create TLS listener: {err:?}")))?;

    let cert_chain_der = cert_iter
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| std::io::Error::other(format!("Failed to create TLS listener: {err:?}")))?;

    let private_key_der = PrivateKeyDer::from_pem_file(&tls_param.key)
        .map_err(|err| std::io::Error::other(format!("Failed to create TLS listener: {err:?}")))?;

    check_privkey_minimums(&private_key_der).map_err(|err| {
        std::io::Error::other(format!("Private key minimums were not met: {err:?}"))
    })?;

    // Configure the rustls cryptoprovider. We currently use aws-lc-rc as the
    // default. We may swap to rustcrypto in future.
    let provider: Arc<_> = rustls::crypto::aws_lc_rs::default_provider().into();

    let client_cert_verifier = if let Some(client_ca) = tls_param.client_ca.as_ref() {
        info!("Loading client certificates from {}", client_ca.display());

        let read_dir = fs::read_dir(client_ca).map_err(|err| {
            std::io::Error::other(format!(
                "Failed to create TLS listener while loading client ca from {}: {:?}",
                client_ca.display(),
                err
            ))
        })?;

        let dirents: Vec<_> = read_dir.filter_map(|item| item.ok()).collect();

        let mut client_cert_roots = RootCertStore::empty();

        for cert_dir_ent in dirents.iter().filter(|item| {
            item.file_name()
                .to_str()
                // Hashed certs end in .0
                // Hashed crls are .r0
                .map(|fname| fname.ends_with(".0"))
                .unwrap_or_default()
        }) {
            let cert_pem = CertificateDer::from_pem_file(cert_dir_ent.path()).map_err(|err| {
                std::io::Error::other(format!("Failed to create TLS listener: {err:?}"))
            })?;

            client_cert_roots.add(cert_pem).map_err(|err| {
                std::io::Error::other(format!("Failed to create TLS listener: {err:?}"))
            })?;
        }

        let mut client_cert_crls = Vec::new();

        for cert_dir_ent in dirents.iter().filter(|item| {
            item.file_name()
                .to_str()
                // Hashed certs end in .0
                // Hashed crls are .r0
                .map(|fname| fname.ends_with(".r0"))
                .unwrap_or_default()
        }) {
            let cert_pem = CertificateRevocationListDer::from_pem_file(cert_dir_ent.path())
                .map_err(|err| {
                    std::io::Error::other(format!("Failed to create TLS listener: {err:?}"))
                })?;

            client_cert_crls.push(cert_pem);
        }

        WebPkiClientVerifier::builder_with_provider(client_cert_roots.into(), provider.clone())
            .with_crls(client_cert_crls)
            .allow_unauthenticated()
            .build()
            .map_err(|err| {
                std::io::Error::other(format!("Failed to create TLS listener: {err:?}"))
            })?
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

    let tls_server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|builder| {
            builder
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(cert_chain_der, private_key_der)
        })
        .map_err(|err| std::io::Error::other(format!("Failed to create TLS listener: {err:?}")))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

    Ok(Some(tls_acceptor))
}

fn get_ec_group() -> Result<EcGroup, ErrorStack> {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
}

#[derive(Debug)]
pub(crate) struct CaHandle {
    key: pkey::PKey<pkey::Private>,
    cert: X509,
}

pub(crate) fn write_ca(
    key_ar: impl AsRef<Path>,
    cert_ar: impl AsRef<Path>,
    handle: &CaHandle,
) -> Result<(), ()> {
    let key_path: &Path = key_ar.as_ref();
    let cert_path: &Path = cert_ar.as_ref();

    let key_pem = handle.key.private_key_to_pem_pkcs8().map_err(|e| {
        error!(err = ?e, "Failed to convert key to PEM");
    })?;

    let cert_pem = handle.cert.to_pem().map_err(|e| {
        error!(err = ?e, "Failed to convert cert to PEM");
    })?;

    fs::File::create(key_path)
        .and_then(|mut file| file.write_all(&key_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", key_path);
        })?;

    fs::File::create(cert_path)
        .and_then(|mut file| file.write_all(&cert_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", cert_path);
        })
}

#[derive(Debug)]
pub enum KeyType {
    #[allow(dead_code)]
    Rsa,
    Ec,
}
impl Default for KeyType {
    fn default() -> Self {
        Self::Ec
    }
}

#[derive(Debug)]
pub struct CAConfig {
    pub key_type: KeyType,
    pub key_bits: u64,
    #[allow(dead_code)]
    pub skip_enforce_minimums: bool,
}

impl Default for CAConfig {
    fn default() -> Self {
        #[allow(clippy::expect_used)]
        Self::new(KeyType::Ec, 256, false)
            .expect("Somehow the defaults failed to pass validation while building a CA Config?")
    }
}

impl CAConfig {
    fn new(key_type: KeyType, key_bits: u64, skip_enforce_minimums: bool) -> Result<Self, String> {
        let res = Self {
            key_type,
            key_bits,
            skip_enforce_minimums,
        };
        if !skip_enforce_minimums {
            res.enforce_minimums()?;
        };
        Ok(res)
    }

    /// Make sure we're meeting the minimum spec for key length etc
    fn enforce_minimums(&self) -> Result<(), String> {
        match self.key_type {
            KeyType::Rsa => {
                trace!(
                    "Generating CA Config for RSA Key with {} bits",
                    self.key_bits
                );
                if self.key_bits < RSA_MIN_KEY_SIZE_BITS {
                    return Err(format!(
                        "RSA key size must be at least {RSA_MIN_KEY_SIZE_BITS} bits"
                    ));
                }
            }
            KeyType::Ec => {
                trace!("Generating CA Config for EcKey with {} bits", self.key_bits);
                if self.key_bits < EC_MIN_KEY_SIZE_BITS {
                    return Err(format!(
                        "EC key size must be at least {EC_MIN_KEY_SIZE_BITS} bits"
                    ));
                }
            }
        };
        Ok(())
    }
}

pub(crate) fn gen_private_key(
    key_type: &KeyType,
    key_bits: Option<u64>,
) -> Result<pkey::PKey<pkey::Private>, ErrorStack> {
    match key_type {
        KeyType::Rsa => {
            let key_bits = key_bits.unwrap_or(RSA_MIN_KEY_SIZE_BITS);
            let rsa = Rsa::generate(key_bits as u32)?;
            pkey::PKey::from_rsa(rsa)
        }
        KeyType::Ec => {
            // TODO: take key bitlength and use it for the curve group, somehow?
            let ecgroup = get_ec_group()?;
            let eckey = EcKey::generate(&ecgroup)?;
            pkey::PKey::from_ec_key(eckey)
        }
    }
}

/// build up a CA certificate and key.
pub(crate) fn build_ca(ca_config: Option<CAConfig>) -> Result<CaHandle, ErrorStack> {
    // We never actually call ca_config from any external input, it's fully internal
    // and controlled by us. Should we remove ca_config instead?
    let ca_config = ca_config.unwrap_or_default();

    // We don't need to check minimums here because we are the ones generating the key.
    let ca_key = gen_private_key(&ca_config.key_type, Some(ca_config.key_bits))?;

    let mut x509_name = X509NameBuilder::new()?;

    x509_name.append_entry_by_text("C", "AU")?;
    x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Kanidm")?;
    x509_name.append_entry_by_text("CN", "Kanidm Generated CA")?;
    x509_name.append_entry_by_text("OU", "Development and Evaluation - NOT FOR PRODUCTION")?;
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
    let not_after = asn1::Asn1Time::days_from_now(CA_VALID_DAYS)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
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

    cert_builder.sign(&ca_key, get_signing_func())?;
    let ca_cert = cert_builder.build();

    Ok(CaHandle {
        key: ca_key,
        cert: ca_cert,
    })
}

pub(crate) fn load_ca(
    ca_key_ar: impl AsRef<Path>,
    ca_cert_ar: impl AsRef<Path>,
) -> Result<CaHandle, ()> {
    let ca_key_path: &Path = ca_key_ar.as_ref();
    let ca_cert_path: &Path = ca_cert_ar.as_ref();

    let mut ca_key_pem = vec![];
    fs::File::open(ca_key_path)
        .and_then(|mut file| file.read_to_end(&mut ca_key_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to read {:?}", ca_key_path);
        })?;

    let mut ca_cert_pem = vec![];
    fs::File::open(ca_cert_path)
        .and_then(|mut file| file.read_to_end(&mut ca_cert_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to read {:?}", ca_cert_path);
        })?;

    let ca_key = pkey::PKey::private_key_from_pem(&ca_key_pem).map_err(|e| {
        error!(err = ?e, "Failed to convert PEM to key");
    })?;

    /*
    check_privkey_minimums(&ca_key).map_err(|err| {
        #[cfg(any(test, debug_assertions))]
        println!("{:?}", err);
        admin_error!("{}", err);
    })?;
    */

    let ca_cert = X509::from_pem(&ca_cert_pem).map_err(|e| {
        error!(err = ?e, "Failed to convert PEM to cert");
    })?;

    Ok(CaHandle {
        key: ca_key,
        cert: ca_cert,
    })
}

pub(crate) struct CertHandle {
    key: pkey::PKey<pkey::Private>,
    cert: X509,
    chain: Vec<X509>,
}

pub(crate) fn write_cert(
    key_ar: impl AsRef<Path>,
    chain_ar: impl AsRef<Path>,
    cert_ar: impl AsRef<Path>,
    handle: &CertHandle,
) -> Result<(), ()> {
    let key_path: &Path = key_ar.as_ref();
    let chain_path: &Path = chain_ar.as_ref();
    let cert_path: &Path = cert_ar.as_ref();

    let key_pem = handle.key.private_key_to_pem_pkcs8().map_err(|e| {
        error!(err = ?e, "Failed to convert key to PEM");
    })?;

    let cert_pem = handle.cert.to_pem().map_err(|e| {
        error!(err = ?e, "Failed to convert cert to PEM");
    })?;

    let mut chain_pem = cert_pem.clone();

    // Build the chain PEM.
    for ca_cert in &handle.chain {
        match ca_cert.to_pem() {
            Ok(c) => {
                chain_pem.extend_from_slice(&c);
            }
            Err(e) => {
                error!(err = ?e, "Failed to convert cert to PEM");
                return Err(());
            }
        }
    }

    fs::File::create(key_path)
        .and_then(|mut file| file.write_all(&key_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", key_path);
        })?;

    fs::File::create(chain_path)
        .and_then(|mut file| file.write_all(&chain_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", chain_path);
        })?;

    fs::File::create(cert_path)
        .and_then(|mut file| file.write_all(&cert_pem))
        .map_err(|e| {
            error!(err = ?e, "Failed to create {:?}", cert_path);
        })
}

pub(crate) fn build_cert(
    domain_name: &str,
    ca_handle: &CaHandle,
    key_type: Option<KeyType>,
    key_bits: Option<u64>,
) -> Result<CertHandle, ErrorStack> {
    let key_type = key_type.unwrap_or_default();
    let int_key = gen_private_key(&key_type, key_bits)?;

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&int_key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "AU")?;
    x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Kanidm")?;
    x509_name.append_entry_by_text("CN", domain_name)?;
    // Requirement of packed attestation.
    x509_name.append_entry_by_text("OU", "Development and Evaluation - NOT FOR PRODUCTION")?;
    let x509_name = x509_name.build();

    req_builder.set_subject_name(&x509_name)?;
    req_builder.sign(&int_key, get_signing_func())?;
    let req = req_builder.build();
    // ==

    let mut cert_builder = X509::builder()?;
    // Yes, 2 actually means 3 here ...
    cert_builder.set_version(2)?;
    let serial_number = bn::BigNum::from_u32(2).and_then(|serial| serial.to_asn1_integer())?;

    cert_builder.set_pubkey(&int_key)?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_handle.cert.subject_name())?;

    let not_before = asn1::Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = asn1::Asn1Time::days_from_now(CERT_VALID_DAYS)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    cert_builder.append_extension(
        ExtendedKeyUsage::new()
            // .critical()
            .server_auth()
            .build()?,
    )?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(Some(&ca_handle.cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(&ca_handle.cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns(domain_name)
        .build(&cert_builder.x509v3_context(Some(&ca_handle.cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.sign(&ca_handle.key, get_signing_func())?;
    let int_cert = cert_builder.build();

    Ok(CertHandle {
        key: int_key,
        cert: int_cert,
        chain: vec![ca_handle.cert.clone()],
    })
}

#[test]
// might as well test my logic
fn test_enforced_minimums() {
    let good_ca_configs = vec![
        // test rsa 4096 (ok)
        (KeyType::Rsa, 4096, false),
        // test rsa 2048 (ok)
        (KeyType::Rsa, 2048, false),
        // test ec 256 (ok)
        (KeyType::Ec, 256, false),
    ];
    good_ca_configs.into_iter().for_each(|config| {
        dbg!(&config);
        assert!(CAConfig::new(config.0, config.1, config.2).is_ok());
    });
    /*
    let bad_ca_configs = vec![
        // test rsa 1024 (no)
        (KeyType::Rsa, 1024, false),
        // test ec 128 (no)
        (KeyType::Ec, 128, false),
    ];
    bad_ca_configs.into_iter().for_each(|config| {
        dbg!(&config);
        assert!(CAConfig::new(config.0, config.1, config.2).is_err());
    });
    */
}

#[test]
fn test_ca_loader() {
    let ca_key_tempfile = tempfile::NamedTempFile::new().unwrap();
    let ca_cert_tempfile = tempfile::NamedTempFile::new().unwrap();
    // let's test the defaults first

    let ca_config = CAConfig::default();
    if let Ok(ca) = build_ca(Some(ca_config)) {
        write_ca(ca_key_tempfile.path(), ca_cert_tempfile.path(), &ca).unwrap();
        assert!(load_ca(ca_key_tempfile.path(), ca_cert_tempfile.path()).is_ok());
    };

    let good_ca_configs = vec![
        // test rsa 4096 (ok)
        (KeyType::Rsa, 4096, false),
        // test rsa 2048 (ok)
        (KeyType::Rsa, 2048, false),
        // test ec 256 (ok)
        (KeyType::Ec, 256, false),
    ];
    good_ca_configs.into_iter().for_each(|config| {
        println!("testing good config {config:?}");
        let ca_config = CAConfig::new(config.0, config.1, config.2).unwrap();
        let ca = build_ca(Some(ca_config)).unwrap();
        write_ca(ca_key_tempfile.path(), ca_cert_tempfile.path(), &ca).unwrap();
        let ca_result = load_ca(ca_key_tempfile.path(), ca_cert_tempfile.path());
        println!("result: {ca_result:?}");
        assert!(ca_result.is_ok());
    });

    /*
    let bad_ca_configs = vec![
        // test rsa 1024 (bad)
        (KeyType::Rsa, 1024, true),
    ];
    bad_ca_configs.into_iter().for_each(|config| {
        println!(
            "\ntesting bad config keytype: {:?} key size: {}, skip_enforce_minimums: {}",
            config.0, config.1, config.2
        );
        let ca_config = CAConfig::new(config.0, config.1, config.2).unwrap();
        let ca = build_ca(Some(ca_config)).unwrap();
        write_ca(ca_key_tempfile.path(), ca_cert_tempfile.path(), &ca).unwrap();
        let ca_result = load_ca(ca_key_tempfile.path(), ca_cert_tempfile.path());
        println!("result: {:?}", ca_result);
        assert!(ca_result.is_err());
    });
    */
}
