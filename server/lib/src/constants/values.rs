use super::uuids::{UUID_DOMAIN_INFO, UUID_SYSTEM_CONFIG, UUID_SYSTEM_INFO};

use crate::value::PartialValue;
use url::Url;

lazy_static! {
    pub static ref URL_SERVICE_DOCUMENTATION: Url =
        #[allow(clippy::expect_used)]
        Url::parse("https://kanidm.github.io/kanidm/master/integrations/oauth2.html")
            .expect("Failed to parse oauth2 service documentation url");
    pub static ref PV_FALSE: PartialValue = PartialValue::new_bool(false);
    pub static ref PVUUID_DOMAIN_INFO: PartialValue = PartialValue::Uuid(UUID_DOMAIN_INFO);
    pub static ref PVUUID_SYSTEM_CONFIG: PartialValue = PartialValue::Uuid(UUID_SYSTEM_CONFIG);
    pub static ref PVUUID_SYSTEM_INFO: PartialValue = PartialValue::Uuid(UUID_SYSTEM_INFO);
}
