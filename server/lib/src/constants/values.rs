use super::uuids::{UUID_DOMAIN_INFO, UUID_SYSTEM_CONFIG, UUID_SYSTEM_INFO};
use crate::value::PartialValue;
use std::sync::LazyLock;
use url::Url;

pub static URL_SERVICE_DOCUMENTATION: LazyLock<Url> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Url::parse("https://kanidm.github.io/kanidm/master/integrations/oauth2.html")
        .expect("Failed to parse oauth2 service documentation url")
});
pub static PV_FALSE: LazyLock<PartialValue> = LazyLock::new(|| PartialValue::new_bool(false));
pub static PVUUID_DOMAIN_INFO: LazyLock<PartialValue> =
    LazyLock::new(|| PartialValue::Uuid(UUID_DOMAIN_INFO));
pub static PVUUID_SYSTEM_CONFIG: LazyLock<PartialValue> =
    LazyLock::new(|| PartialValue::Uuid(UUID_SYSTEM_CONFIG));
pub static PVUUID_SYSTEM_INFO: LazyLock<PartialValue> =
    LazyLock::new(|| PartialValue::Uuid(UUID_SYSTEM_INFO));
