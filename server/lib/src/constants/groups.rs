use crate::entry::EntryInitNew;
use crate::prelude::*;

use kanidm_proto::v1::{Filter, OperationError, UiHint};

#[derive(Clone, Debug, Default)]
/// Built-in group definitions
pub struct BuiltinGroup {
    pub name: &'static str,
    pub description: &'static str,
    pub uuid: uuid::Uuid,
    pub members: Vec<uuid::Uuid>,
    pub entry_managed_by: Option<uuid::Uuid>,
    pub dyngroup: bool,
    pub dyngroup_filter: Option<Filter>,
    pub extra_attributes: Vec<(Attribute, Value)>,
}

impl TryFrom<BuiltinGroup> for EntryInitNew {
    type Error = OperationError;

    fn try_from(val: BuiltinGroup) -> Result<Self, OperationError> {
        let mut entry = EntryInitNew::new();

        entry.add_ava(Attribute::Name, Value::new_iname(val.name));
        entry.add_ava(Attribute::Description, Value::new_utf8s(val.description));
        // classes for groups
        entry.set_ava(
            Attribute::Class,
            vec![EntryClass::Group.into(), EntryClass::Object.into()],
        );
        if val.dyngroup {
            if !val.members.is_empty() {
                return Err(OperationError::InvalidSchemaState(format!(
                    "Builtin dyngroup {} has members specified, this is not allowed",
                    val.name
                )));
            }
            entry.add_ava(Attribute::Class, EntryClass::DynGroup.to_value());
            match val.dyngroup_filter {
                Some(filter) => entry.add_ava(Attribute::DynGroupFilter, Value::JsonFilt(filter)),
                None => {
                    error!(
                        "No filter specified for dyngroup '{}' this is going to break things!",
                        val.name
                    );
                    return Err(OperationError::FilterGeneration);
                }
            };
        }

        if let Some(entry_manager) = val.entry_managed_by {
            entry.add_ava(Attribute::EntryManagedBy, Value::Refer(entry_manager));
        }

        entry.add_ava(Attribute::Uuid, Value::Uuid(val.uuid));
        entry.set_ava(
            Attribute::Member,
            val.members
                .into_iter()
                .map(Value::Refer)
                .collect::<Vec<Value>>(),
        );
        // add any extra attributes
        val.extra_attributes
            .into_iter()
            .for_each(|(attr, val)| entry.add_ava(attr, val));
        // all done!
        Ok(entry)
    }
}

lazy_static! {
    // There are our built in "roles". They encapsulate some higher level collections
    // of roles. The intent is to allow a pretty generic and correct by default set
    // of these use cases.

    pub static ref BUILTIN_GROUP_SYSTEM_ADMINS_V1: BuiltinGroup = BuiltinGroup {
        name: "system_admins",
        description: "Builtin System Administrators Group.",
        uuid: UUID_SYSTEM_ADMINS,
        entry_managed_by: Some(UUID_SYSTEM_ADMINS),
        members: vec![UUID_ADMIN],
        ..Default::default()
    };

    pub static ref BUILTIN_GROUP_IDM_ADMINS_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_admins",
        description: "Builtin IDM Administrators Group.",
        uuid: UUID_IDM_ADMINS,
        entry_managed_by: Some(UUID_IDM_ADMINS),
        members: vec![UUID_IDM_ADMIN],
        ..Default::default()
    };

    pub static ref BUILTIN_GROUP_SERVICE_DESK: BuiltinGroup = BuiltinGroup {
        name: "idm_service_desk",
        description: "Builtin Service Desk Group.",
        uuid: UUID_IDM_SERVICE_DESK,
        entry_managed_by: Some(UUID_IDM_ADMINS),
        members: vec![],
        ..Default::default()
    };

    // These are the "finer" roles. They encapsulate different concepts in the system.
    // The next section is the "system style" roles. These adjust the operation of
    // kanidm and relate to it's internals and how it functions.
    pub static ref BUILTIN_GROUP_RECYCLE_BIN_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "idm_recycle_bin_admins",
        description: "Builtin Recycle Bin Administrators Group.",
        uuid: UUID_IDM_RECYCLE_BIN_ADMINS,
        entry_managed_by: Some(UUID_SYSTEM_ADMINS),
        members: vec![UUID_SYSTEM_ADMINS],
        ..Default::default()
    };

    /// Builtin IDM Group for granting local domain administration rights and trust administration rights
    pub static ref BUILTIN_GROUP_DOMAIN_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "domain_admins",
        description: "Builtin IDM Group for granting local domain administration rights and trust administration rights.",
        uuid: UUID_DOMAIN_ADMINS,
        entry_managed_by: Some(UUID_SYSTEM_ADMINS),
        members: vec![UUID_SYSTEM_ADMINS],
        ..Default::default()
    };

    pub static ref BUILTIN_GROUP_SCHEMA_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "idm_schema_admins",
        description: "Builtin Schema Administration Group.",
        uuid: UUID_IDM_SCHEMA_ADMINS,
        entry_managed_by: Some(UUID_SYSTEM_ADMINS),
        members: vec![UUID_SYSTEM_ADMINS],
        ..Default::default()
    };

    pub static ref BUILTIN_GROUP_ACCESS_CONTROL_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "idm_access_control_admins",
        description: "Builtin Access Control Administration Group.",
        entry_managed_by: Some(UUID_SYSTEM_ADMINS),
        uuid: UUID_IDM_ACCESS_CONTROL_ADMINS,
        members: vec![UUID_SYSTEM_ADMINS],
        ..Default::default()
    };

    // These are the IDM roles. They concern application integration, user permissions
    // and credential security management.

    /// Builtin IDM Group for managing oauth2 resource server integrations to this authentication domain.
    pub static ref BUILTIN_GROUP_OAUTH2_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "idm_oauth2_admins",
        description: "Builtin Oauth2 Integration Administration Group.",
        uuid: UUID_IDM_OAUTH2_ADMINS,
        entry_managed_by: Some(UUID_IDM_ADMINS),
        members: vec![UUID_IDM_ADMINS],
        ..Default::default()
    };

    pub static ref BUILTIN_GROUP_RADIUS_SERVICE_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "idm_radius_service_admins",
        description: "Builtin Radius Administration Group.",
        uuid: UUID_IDM_RADIUS_ADMINS,
        entry_managed_by: Some(UUID_IDM_ADMINS),
        members: vec![UUID_IDM_ADMINS],
        ..Default::default()
    };

    /// Builtin IDM Group for RADIUS server access delegation.
    pub static ref IDM_RADIUS_SERVERS_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_radius_servers",
        description: "Builtin IDM Group for RADIUS server access delegation.",
        uuid: UUID_IDM_RADIUS_SERVERS,
        entry_managed_by: Some(UUID_IDM_RADIUS_ADMINS),
        members: vec![
        ],
        ..Default::default()
    };

    pub static ref BUILTIN_GROUP_ACCOUNT_POLICY_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "idm_account_policy_admins",
        description: "Builtin Account Policy Administration Group.",
        uuid: UUID_IDM_ACCOUNT_POLICY_ADMINS,
        entry_managed_by: Some(UUID_IDM_ADMINS),
        members: vec![UUID_IDM_ADMINS],
        ..Default::default()
    };


// * People read managers
    /// Builtin IDM Group for granting elevated people (personal data) read permissions.
    pub static ref IDM_PEOPLE_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_read_priv",
        description: "Builtin IDM Group for granting elevated people (personal data) read permissions.",
        uuid: UUID_IDM_PEOPLE_READ_PRIV,
        members: vec![UUID_IDM_PEOPLE_WRITE_PRIV],
        ..Default::default()
    };

    pub static ref IDM_PEOPLE_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_write_priv",
        description: "Builtin IDM Group for granting elevated people (personal data) write permissions.",
        uuid: UUID_IDM_PEOPLE_WRITE_PRIV,
        members: vec![UUID_IDM_PEOPLE_MANAGE_PRIV,UUID_IDM_PEOPLE_EXTEND_PRIV],
        ..Default::default()
    };

// * People write managers
    /// Builtin IDM Group for granting elevated people (personal data) write and lifecycle management permissions.
    pub static ref IDM_PEOPLE_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_manage_priv",
        description: "Builtin IDM Group for granting elevated people (personal data) write and lifecycle management permissions.",
        uuid: UUID_IDM_PEOPLE_MANAGE_PRIV,
        members: vec![UUID_IDM_ADMINS],
        ..Default::default()
    };

    /// Builtin IDM Group for allowing the ability to extend accounts to have the "person" flag set.
    pub static ref IDM_PEOPLE_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_extend_priv",
        description: "Builtin System Administrators Group.",
        uuid: UUID_IDM_PEOPLE_EXTEND_PRIV,
        members: vec![UUID_SYSTEM_ADMINS],
        ..Default::default()
    };
    /// Self-write of mail
    pub static ref IDM_PEOPLE_SELF_WRITE_MAIL_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_self_write_mail_priv",
        description: "Builtin IDM Group for people accounts to update their own mail.",
        uuid: UUID_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV,
        members: Vec::new(),
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated high privilege people (personal data) read permissions.
    pub static ref IDM_HP_PEOPLE_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_people_read_priv",
        description: "Builtin IDM Group for granting elevated high privilege people (personal data) read permissions.",
        uuid: UUID_IDM_HP_PEOPLE_READ_PRIV,
        members: vec![UUID_IDM_HP_PEOPLE_WRITE_PRIV],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated high privilege people (personal data) write permissions.
    pub static ref IDM_HP_PEOPLE_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_people_write_priv",
        description: "Builtin IDM Group for granting elevated high privilege people (personal data) write permissions.",
        uuid: UUID_IDM_HP_PEOPLE_WRITE_PRIV,
        members: vec![UUID_IDM_HP_PEOPLE_EXTEND_PRIV],
        ..Default::default()
    };

    /// Builtin IDM Group for extending high privilege accounts to be people.
    pub static ref IDM_HP_PEOPLE_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_people_extend_priv",
        description: "Builtin IDM Group for extending high privilege accounts to be people.",
        uuid: UUID_IDM_HP_PEOPLE_EXTEND_PRIV,
        members: vec![UUID_SYSTEM_ADMINS],
        ..Default::default()
    };

// * group write manager (no read, everyone has read via the anon, etc)

    /// Builtin IDM Group for granting elevated group write and lifecycle permissions.
    pub static ref IDM_GROUP_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_group_manage_priv",
        description: "Builtin IDM Group for granting elevated group write and lifecycle permissions.",
        uuid: UUID_IDM_GROUP_MANAGE_PRIV,
        members: vec![
            BUILTIN_GROUP_IDM_ADMINS_V1.uuid,
            BUILTIN_GROUP_SYSTEM_ADMINS_V1.uuid,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated group write and lifecycle permissions.
    pub static ref IDM_GROUP_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_group_write_priv",
        description: "Builtin IDM Group for granting elevated group write permissions.",
        uuid: UUID_IDM_GROUP_WRITE_PRIV,
        members: vec![
            UUID_IDM_GROUP_MANAGE_PRIV
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting unix group extension permissions.
    pub static ref IDM_GROUP_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_group_unix_extend_priv",
        description: "Builtin IDM Group for granting UNIX group extension permissions.",
        uuid: UUID_IDM_GROUP_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_IDM_ADMINS
        ],
        ..Default::default()
    };

    /// Account read manager
    pub static ref IDM_ACCOUNT_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_read_priv",
        description: "Builtin IDM Group for granting elevated account read permissions.",
        uuid: UUID_IDM_ACCOUNT_READ_PRIV,
        members: vec![
            UUID_IDM_ACCOUNT_WRITE_PRIV,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACCOUNT_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_manage_priv",
        description: "Builtin IDM Group for granting elevated account write and lifecycle permissions.",
        uuid: UUID_IDM_ACCOUNT_MANAGE_PRIV,
        members: vec![
            UUID_IDM_ADMINS,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACCOUNT_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_write_priv",
        description: "Builtin IDM Group for granting elevated account write permissions.",
        uuid: UUID_IDM_ACCOUNT_WRITE_PRIV,
        members: vec![
            UUID_IDM_ACCOUNT_MANAGE_PRIV,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACCOUNT_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_unix_extend_priv",
        description: "Builtin IDM Group for granting account unix extend permissions.",
        uuid: UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_IDM_ADMINS,
        ],
        ..Default::default()
    };

    /// High privilege account read manager
    pub static ref IDM_HP_ACCOUNT_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_read_priv",
        description: "Builtin IDM Group for granting elevated account read permissions over high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_READ_PRIV,
        members: vec![
            UUID_IDM_HP_ACCOUNT_WRITE_PRIV
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated account write permissions over high privilege accounts.
    pub static ref IDM_HP_ACCOUNT_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_manage_priv",
        description: "Builtin IDM Group for granting elevated account write and lifecycle permissions over high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };
    /// Builtin IDM Group for granting elevated account write permissions over high privilege accounts.
    pub static ref IDM_HP_ACCOUNT_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_write_priv",
        description: "Builtin IDM Group for granting elevated account write permissions over high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_WRITE_PRIV,
        members: vec![
            UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting account unix extend permissions for high privilege accounts.
    pub static ref IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_unix_extend_priv",
        description: "Builtin IDM Group for granting account UNIX extend permissions for high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups.
    pub static ref IDM_HP_GROUP_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_group_manage_priv",
        description: "Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups.",
        uuid: UUID_IDM_HP_GROUP_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated group write privileges for high privilege groups.
    pub static ref IDM_HP_GROUP_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_group_write_priv",
        description: "Builtin IDM Group for granting elevated group write privileges for high privilege groups.",
        uuid: UUID_IDM_HP_GROUP_WRITE_PRIV,
        members: vec![
            UUID_IDM_HP_GROUP_MANAGE_PRIV,
        ],
        ..Default::default()
    };

}
// at some point vs code just gives up on syntax highlighting inside lazy_static...
lazy_static! {

    /// Builtin IDM Group for granting unix group extension permissions for high privilege groups.
    pub static ref IDM_HP_GROUP_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_group_unix_extend_priv",
        description: "Builtin IDM Group for granting unix group extension permissions for high privilege groups.",
        uuid: UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for allowing migrations of service accounts into persons
    pub static ref IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_service_account_into_person_migrate_priv",
        description:"Builtin IDM Group for allowing migrations of service accounts into persons",
        uuid: UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    pub static ref IDM_ALL_PERSONS: BuiltinGroup = BuiltinGroup {
        name: "idm_all_persons",
        description: "Builtin IDM dynamic group containing all persons.",
        uuid: UUID_IDM_ALL_PERSONS,
        members: Vec::new(),
        dyngroup: true,
        dyngroup_filter: Some(
            Filter::And(vec![
                Filter::Eq(Attribute::Class.to_string(), EntryClass::Person.to_string()),
                Filter::Eq(Attribute::Class.to_string(), EntryClass::Account.to_string()),
            ])
        ),
        extra_attributes: vec![
            // Enable account policy by default
            (Attribute::Class, EntryClass::AccountPolicy.to_value()),
            // Enforce this is a system protected object
            (Attribute::Class, EntryClass::System.to_value()),
        ],
        ..Default::default()
    };

    pub static ref IDM_ALL_ACCOUNTS: BuiltinGroup = BuiltinGroup {
        name: "idm_all_accounts",
        description: "Builtin IDM dynamic group containing all entries that can authenticate.",
        uuid: UUID_IDM_ALL_ACCOUNTS,
        members: Vec::new(),
        dyngroup: true,
        dyngroup_filter: Some(
                Filter::Eq(Attribute::Class.to_string(), EntryClass::Account.to_string()),
        ),
        extra_attributes: vec![
            // Enable account policy by default
            (Attribute::Class, EntryClass::AccountPolicy.to_value()),
            // Enforce this is a system protected object
            (Attribute::Class, EntryClass::System.to_value()),
        ],
        ..Default::default()
    };


    pub static ref IDM_UI_ENABLE_EXPERIMENTAL_FEATURES: BuiltinGroup = BuiltinGroup {
        name: "idm_ui_enable_experimental_features",
        description: "Members of this group will have access to experimental web UI features.",
        uuid: UUID_IDM_UI_ENABLE_EXPERIMENTAL_FEATURES,
        extra_attributes: vec![
            (Attribute::GrantUiHint, Value::UiHint(UiHint::ExperimentalFeatures))
        ],
        ..Default::default()
    };

    /// Members of this group will have access to read the mail attribute of all persons and service accounts.
    pub static ref IDM_ACCOUNT_MAIL_READ_PRIV: BuiltinGroup = BuiltinGroup {
        name: "idm_account_mail_read_priv",
        description: "Members of this group will have access to read the mail attribute of all persons and service accounts.",
        uuid: UUID_IDM_ACCOUNT_MAIL_READ_PRIV,
        ..Default::default()
    };

    /// This must be the last group to init to include the UUID of the other high priv groups.
    pub static ref IDM_HIGH_PRIVILEGE_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_high_privilege",
        uuid: UUID_IDM_HIGH_PRIVILEGE,
        description: "Builtin IDM provided groups with high levels of access that should be audited and limited in modification.",
        members: vec![
            UUID_SYSTEM_ADMINS,
            UUID_IDM_ADMINS,
            UUID_DOMAIN_ADMINS,
            UUID_IDM_SERVICE_DESK,
            UUID_IDM_RECYCLE_BIN_ADMINS,
            UUID_IDM_SCHEMA_ADMINS,
            UUID_IDM_ACCESS_CONTROL_ADMINS,
            UUID_IDM_OAUTH2_ADMINS,
            UUID_IDM_RADIUS_ADMINS,
            UUID_IDM_ACCOUNT_POLICY_ADMINS,
            UUID_IDM_RADIUS_SERVERS,


            UUID_IDM_HIGH_PRIVILEGE,
            // TBD

            UUID_IDM_PEOPLE_READ_PRIV,
            UUID_IDM_PEOPLE_WRITE_PRIV,
            UUID_IDM_GROUP_WRITE_PRIV,
            UUID_IDM_ACCOUNT_READ_PRIV,
            UUID_IDM_ACCOUNT_WRITE_PRIV,
            UUID_IDM_HP_ACCOUNT_READ_PRIV,
            UUID_IDM_HP_ACCOUNT_WRITE_PRIV,
            UUID_IDM_HP_GROUP_WRITE_PRIV,
            UUID_IDM_PEOPLE_MANAGE_PRIV,
            UUID_IDM_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_GROUP_MANAGE_PRIV,
            UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_HP_GROUP_MANAGE_PRIV,
            UUID_IDM_PEOPLE_EXTEND_PRIV,
            UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV,
            UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV,
            UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
        ],
        ..Default::default()
    };
}

/// Make a list of all the non-admin BuiltinGroup's that are created by default, doing it in a standard-ish way so we can use it around the platform
pub fn idm_builtin_non_admin_groups() -> Vec<&'static BuiltinGroup> {
    // Create any system default schema entries.
    vec![
        &BUILTIN_GROUP_DOMAIN_ADMINS,
        // &IDM_HP_OAUTH2_MANAGE_PRIV_V1,
        &BUILTIN_GROUP_SCHEMA_ADMINS,
        &BUILTIN_GROUP_ACCESS_CONTROL_ADMINS,
        &BUILTIN_GROUP_RECYCLE_BIN_ADMINS,
        &BUILTIN_GROUP_SERVICE_DESK,
        &BUILTIN_GROUP_OAUTH2_ADMINS,
        &BUILTIN_GROUP_RADIUS_SERVICE_ADMINS,
        &BUILTIN_GROUP_ACCOUNT_POLICY_ADMINS,
        &IDM_ALL_PERSONS,
        &IDM_ALL_ACCOUNTS,
        &IDM_RADIUS_SERVERS_V1,
        &IDM_PEOPLE_MANAGE_PRIV_V1,
        &IDM_PEOPLE_EXTEND_PRIV_V1,
        &IDM_PEOPLE_SELF_WRITE_MAIL_PRIV_V1,
        &IDM_PEOPLE_WRITE_PRIV_V1,
        &IDM_PEOPLE_READ_PRIV_V1,
        &IDM_HP_PEOPLE_EXTEND_PRIV_V1,
        &IDM_HP_PEOPLE_WRITE_PRIV_V1,
        &IDM_HP_PEOPLE_READ_PRIV_V1,
        &IDM_GROUP_MANAGE_PRIV_V1,
        &IDM_GROUP_WRITE_PRIV_V1,
        &IDM_GROUP_UNIX_EXTEND_PRIV_V1,
        &IDM_ACCOUNT_MANAGE_PRIV_V1,
        &IDM_ACCOUNT_WRITE_PRIV_V1,
        &IDM_ACCOUNT_UNIX_EXTEND_PRIV_V1,
        &IDM_ACCOUNT_READ_PRIV_V1,
        // Write deps on read, so write must be added first.
        &IDM_HP_ACCOUNT_MANAGE_PRIV_V1,
        &IDM_HP_ACCOUNT_WRITE_PRIV_V1,
        &IDM_HP_ACCOUNT_READ_PRIV_V1,
        &IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
        &IDM_HP_GROUP_MANAGE_PRIV_V1,
        &IDM_HP_GROUP_WRITE_PRIV_V1,
        &IDM_HP_GROUP_UNIX_EXTEND_PRIV_V1,
        &IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
        // All members must exist before we write HP
        &IDM_HIGH_PRIVILEGE_V1,
        // other things
        &IDM_UI_ENABLE_EXPERIMENTAL_FEATURES,
        &IDM_ACCOUNT_MAIL_READ_PRIV,
    ]
}

pub fn idm_builtin_admin_groups() -> Vec<&'static BuiltinGroup> {
    vec![
        &BUILTIN_GROUP_SYSTEM_ADMINS_V1,
        &BUILTIN_GROUP_IDM_ADMINS_V1,
    ]
}
