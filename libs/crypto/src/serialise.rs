pub mod pkeyb64 {
    use base64::{engine::general_purpose, Engine as _};
    use openssl::pkey::{PKey, Private};
    use serde::{
        de::Error as DeError, ser::Error as SerError, Deserialize, Deserializer, Serializer,
    };
    use tracing::error;

    pub fn serialize<S>(key: &PKey<Private>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let der = key.private_key_to_der().map_err(|err| {
            error!(?err, "openssl private_key_to_der");
            S::Error::custom("openssl private_key_to_der")
        })?;
        let s = general_purpose::URL_SAFE.encode(der);

        ser.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(des: D) -> Result<PKey<Private>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = <&str>::deserialize(des)?;
        let s = general_purpose::URL_SAFE.decode(raw).map_err(|err| {
            error!(?err, "base64 url-safe invalid");
            D::Error::custom("base64 url-safe invalid")
        })?;

        PKey::private_key_from_der(&s).map_err(|err| {
            error!(?err, "openssl pkey invalid der");
            D::Error::custom("openssl pkey invalid der")
        })
    }
}

pub mod x509b64 {
    use crate::CryptoError;
    use base64::{engine::general_purpose, Engine as _};
    use openssl::x509::X509;
    use serde::{
        de::Error as DeError, ser::Error as SerError, Deserialize, Deserializer, Serializer,
    };
    use tracing::error;

    pub fn cert_to_string(cert: &X509) -> Result<String, CryptoError> {
        cert.to_der()
            .map_err(|err| {
                error!(?err, "openssl cert to_der");
                err.into()
            })
            .map(|der| general_purpose::URL_SAFE.encode(der))
    }

    pub fn serialize<S>(cert: &X509, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let der = cert.to_der().map_err(|err| {
            error!(?err, "openssl cert to_der");
            S::Error::custom("openssl private_key_to_der")
        })?;
        let s = general_purpose::URL_SAFE.encode(der);

        ser.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(des: D) -> Result<X509, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = <&str>::deserialize(des)?;
        let s = general_purpose::URL_SAFE.decode(raw).map_err(|err| {
            error!(?err, "base64 url-safe invalid");
            D::Error::custom("base64 url-safe invalid")
        })?;

        X509::from_der(&s).map_err(|err| {
            error!(?err, "openssl x509 invalid der");
            D::Error::custom("openssl x509 invalid der")
        })
    }
}
