use webauthn_rs::WebauthnConfig;

pub struct WebauthnDomainConfig {
    pub rp_name: String,
    pub origin: String,
    pub rp_id: String,
}

impl WebauthnConfig for WebauthnDomainConfig {
    fn get_relying_party_name(&self) -> &str {
        self.rp_name.as_str()
    }

    fn get_origin(&self) -> &str {
        self.origin.as_str()
    }

    fn get_relying_party_id(&self) -> &str {
        self.rp_id.as_str()
    }
}
