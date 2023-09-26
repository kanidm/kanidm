use crate::CryptoError;

use openssl::asn1;
use openssl::bn;
use openssl::ec;
use openssl::error::ErrorStack as OpenSSLError;
use openssl::hash;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::ExtendedKeyUsage;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509;

use uuid::Uuid;

/// Gets an [EcGroup] for P-256
pub fn get_group() -> Result<ec::EcGroup, OpenSSLError> {
    ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
}

pub fn build_self_signed_server_and_client_identity(
    cn: Uuid,
    domain_name: &str,
    expiration_days: u32,
) -> Result<(PKey<Private>, X509), CryptoError> {
    let ecgroup = get_group()?;
    let eckey = ec::EcKey::generate(&ecgroup)?;
    let ca_key = PKey::from_ec_key(eckey)?;
    let mut x509_name = X509NameBuilder::new()?;

    // x509_name.append_entry_by_text("C", "AU")?;
    // x509_name.append_entry_by_text("ST", "QLD")?;
    x509_name.append_entry_by_text("O", "Kanidm Replication")?;
    x509_name.append_entry_by_text("CN", &cn.as_hyphenated().to_string())?;
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
    let not_after = asn1::Asn1Time::days_from_now(expiration_days)?;
    cert_builder.set_not_after(&not_after)?;

    // Do we need pathlen 0?
    cert_builder.append_extension(BasicConstraints::new().critical().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    cert_builder.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns(domain_name)
        .build(&cert_builder.x509v3_context(None, None))?;

    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.set_pubkey(&ca_key)?;

    cert_builder.sign(&ca_key, hash::MessageDigest::sha256())?;
    let ca_cert = cert_builder.build();

    Ok((ca_key, ca_cert))
}
