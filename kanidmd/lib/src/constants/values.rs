use super::uuids::UUID_DOMAIN_INFO;
use crate::value::{PartialValue, Value};
use url::Url;

lazy_static! {
    pub static ref URL_SERVICE_DOCUMENTATION: Url =
        #[allow(clippy::expect_used)]
        Url::parse("https://kanidm.github.io/kanidm/master/integrations/oauth2.html")
            .expect("Failed to parse oauth2 service documentation url");
    pub static ref PV_FALSE: PartialValue = PartialValue::new_bool(false);
    pub static ref PVCLASS_ACCOUNT: PartialValue = PartialValue::new_class("account");
    pub static ref PVCLASS_ACS: PartialValue = PartialValue::new_class("access_control_search");
    pub static ref PVCLASS_ACC: PartialValue = PartialValue::new_class("access_control_create");
    pub static ref PVCLASS_ACD: PartialValue = PartialValue::new_class("access_control_delete");
    pub static ref PVCLASS_ACM: PartialValue = PartialValue::new_class("access_control_modify");
    pub static ref PVCLASS_ACP: PartialValue = PartialValue::new_class("access_control_profile");
    pub static ref PVCLASS_ATTRIBUTETYPE: PartialValue = PartialValue::new_class("attributetype");
    pub static ref PVCLASS_CLASSTYPE: PartialValue = PartialValue::new_class("classtype");
    pub static ref PVCLASS_DOMAIN_INFO: PartialValue = PartialValue::new_class("domain_info");
    pub static ref PVCLASS_DYNGROUP: PartialValue = PartialValue::new_class("dyngroup");
    pub static ref PVCLASS_EXTENSIBLE: PartialValue = PartialValue::new_class("extensibleobject");
    pub static ref PVCLASS_GROUP: PartialValue = PartialValue::new_class("group");
    pub static ref PVCLASS_OAUTH2_RS: PartialValue =
        PartialValue::new_class("oauth2_resource_server");
    pub static ref PVCLASS_OAUTH2_BASIC: PartialValue =
        PartialValue::new_class("oauth2_resource_server_basic");
    pub static ref PVCLASS_PERSON: PartialValue = PartialValue::new_class("person");
    pub static ref PVCLASS_POSIXACCOUNT: PartialValue = PartialValue::new_class("posixaccount");
    pub static ref PVCLASS_POSIXGROUP: PartialValue = PartialValue::new_class("posixgroup");
    pub static ref PVCLASS_RECYCLED: PartialValue = PartialValue::new_class("recycled");
    pub static ref PVCLASS_SERVICE_ACCOUNT: PartialValue =
        PartialValue::new_class("service_account");
    pub static ref PVCLASS_SYNC_ACCOUNT: PartialValue = PartialValue::new_class("sync_account");
    pub static ref PVCLASS_SYNC_OBJECT: PartialValue = PartialValue::new_class("sync_object");
    pub static ref PVCLASS_SYSTEM: PartialValue = PartialValue::new_class("system");
    pub static ref PVCLASS_SYSTEM_INFO: PartialValue = PartialValue::new_class("system_info");
    pub static ref PVCLASS_SYSTEM_CONFIG: PartialValue = PartialValue::new_class("system_config");
    pub static ref PVCLASS_TOMBSTONE: PartialValue = PartialValue::new_class("tombstone");
    pub static ref PVUUID_DOMAIN_INFO: PartialValue = PartialValue::Uuid(UUID_DOMAIN_INFO);
    pub static ref CLASS_ACCESS_CONTROL_PROFILE: Value = Value::new_class("access_control_profile");
    pub static ref CLASS_ACCESS_CONTROL_SEARCH: Value = Value::new_class("access_control_search");
    pub static ref CLASS_ACCOUNT: Value = Value::new_class("account");
    pub static ref CLASS_ATTRIBUTETYPE: Value = Value::new_class("attributetype");
    pub static ref CLASS_CLASS: Value = Value::new_class("class");
    pub static ref CLASS_DOMAIN_INFO: Value = Value::new_class("domain_info");
    pub static ref CLASS_DYNGROUP: Value = Value::new_class("dyngroup");
    pub static ref CLASS_GROUP: Value = Value::new_class("group");
    pub static ref CLASS_MEMBEROF: Value = Value::new_class("memberof");
    pub static ref CLASS_OBJECT: Value = Value::new_class("object");
    pub static ref CLASS_PERSON: Value = Value::new_class("person");
    pub static ref CLASS_RECYCLED: Value = Value::new_class("recycled");
    pub static ref CLASS_SERVICE_ACCOUNT: Value = Value::new_class("service_account");
    pub static ref CLASS_SYNC_OBJECT: Value = Value::new_class("sync_object");
    pub static ref CLASS_SYSTEM: Value = Value::new_class("system");
    pub static ref CLASS_SYSTEM_CONFIG: Value = Value::new_class("system_config");
    pub static ref CLASS_SYSTEM_INFO: Value = Value::new_class("system_info");
    pub static ref CLASS_TOMBSTONE: Value = Value::new_class("tombstone");
}
