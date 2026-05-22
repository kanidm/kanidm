use crate::prelude::*;
use crate::schema::Replicated;

pub static SCHEMA_ATTR_CLASS: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Class,
    uuid: UUID_SCHEMA_ATTR_CLASS,
    description: String::from("The set of classes defining an object"),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_UUID: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Uuid,
    uuid: UUID_SCHEMA_ATTR_UUID,
    description: String::from("The universal unique id of the object"),
    multivalue: false,
    // Uniqueness is handled by base.rs, not attrunique here due to
    // needing to check recycled objects too.
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::Uuid,
});
pub static SCHEMA_ATTR_SOURCE_UUID: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::SourceUuid,
    uuid: UUID_SCHEMA_ATTR_SOURCE_UUID,
    description: String::from(
        "The universal unique id of the source object(s) which conflicted with this entry",
    ),
    multivalue: true,
    // Uniqueness is handled by base.rs, not attrunique here due to
    // needing to check recycled objects too.
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::Uuid,
});
pub static SCHEMA_ATTR_CREATED_AT_CID: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::CreatedAtCid,
        uuid: UUID_SCHEMA_ATTR_CREATED_AT_CID,
        description: String::from("The cid when this entry was created"),
        multivalue: false,
        // Uniqueness is handled by base.rs, not attrunique here due to
        // needing to check recycled objects too.
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::Cid,
    });
pub static SCHEMA_ATTR_LAST_MODIFIED_CID: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::LastModifiedCid,
        uuid: UUID_SCHEMA_ATTR_LAST_MOD_CID,
        description: String::from("The cid of the last change to this object"),
        multivalue: false,
        // Uniqueness is handled by base.rs, not attrunique here due to
        // needing to check recycled objects too.
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::Cid,
    });
pub static SCHEMA_ATTR_NAME: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Name,
    uuid: UUID_SCHEMA_ATTR_NAME,
    description: String::from("The shortform name of an object"),
    multivalue: false,
    unique: true,
    phantom: false,
    sync_allowed: true,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::Utf8StringIname,
});
pub static SCHEMA_ATTR_SPN: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Spn,
    uuid: UUID_SCHEMA_ATTR_SPN,
    description: String::from(
        "The Security Principal Name of an object, unique across all domain trusts",
    ),
    multivalue: false,
    unique: true,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::SecurityPrincipalName,
});
pub static SCHEMA_ATTR_ATTRIBUTE_NAME: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AttributeName,
        uuid: UUID_SCHEMA_ATTR_ATTRIBUTENAME,
        description: String::from("The name of a schema attribute"),
        multivalue: false,
        unique: true,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_CLASS_NAME: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::ClassName,
    uuid: UUID_SCHEMA_ATTR_CLASSNAME,
    description: String::from("The name of a schema class"),
    multivalue: false,
    unique: true,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_DESCRIPTION: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Description,
    uuid: UUID_SCHEMA_ATTR_DESCRIPTION,
    description: String::from("A description of an attribute, object or class"),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: true,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8String,
});
pub static SCHEMA_ATTR_MULTI_VALUE: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::MultiValue,
    uuid: UUID_SCHEMA_ATTR_MULTIVALUE,
    description: String::from(
        "If true, this attribute is able to store multiple values rather than just a single value.",
    ),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Boolean,
});
pub static SCHEMA_ATTR_PHANTOM: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                name: Attribute::Phantom,
                uuid: UUID_SCHEMA_ATTR_PHANTOM,
                description: String::from("If true, this attribute must NOT be present in any may/must sets of a class as. This represents generated attributes."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Boolean,
            }
});
pub static SCHEMA_ATTR_SYNC_ALLOWED: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::SyncAllowed,
        uuid: UUID_SCHEMA_ATTR_SYNC_ALLOWED,
        description: String::from(
            "If true, this attribute or class can by synchronised by an external scim import",
        ),
        multivalue: false,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: false,
        syntax: SyntaxType::Boolean,
    });
pub static SCHEMA_ATTR_REPLICATED: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Replicated,
    uuid: UUID_SCHEMA_ATTR_REPLICATED,
    description: String::from(
        "If true, this attribute or class can by replicated between nodes in the topology",
    ),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Boolean,
});
pub static SCHEMA_ATTR_UNIQUE: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Unique,
    uuid: UUID_SCHEMA_ATTR_UNIQUE,
    description: String::from(
        "If true, this attribute must store a unique value through out the database.",
    ),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Boolean,
});
pub static SCHEMA_ATTR_INDEX: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Index,
    uuid: UUID_SCHEMA_ATTR_INDEX,
    description: String::from("Describe the indexes to apply to instances of this attribute."),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::IndexId,
});
pub static SCHEMA_ATTR_INDEXED: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Indexed,
    uuid: UUID_SCHEMA_ATTR_INDEXED,
    description: String::from(
        "A boolean stating if this attribute will be indexed according to its syntax rules.",
    ),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Boolean,
});
pub static SCHEMA_ATTR_SYNTAX: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Syntax,
    uuid: UUID_SCHEMA_ATTR_SYNTAX,
    description: String::from(
        "Describe the syntax of this attribute. This affects indexing and sorting.",
    ),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::SyntaxId,
});
pub static SCHEMA_ATTR_SYSTEM_MAY: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::SystemMay,
    uuid: UUID_SCHEMA_ATTR_SYSTEMMAY,
    description: String::from(
        "A list of system provided optional attributes this class can store.",
    ),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_MAY: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::May,
    uuid: UUID_SCHEMA_ATTR_MAY,
    description: String::from(
        "A user modifiable list of optional attributes this class can store.",
    ),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_SYSTEM_MUST: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::SystemMust,
    uuid: UUID_SCHEMA_ATTR_SYSTEMMUST,
    description: String::from(
        "A list of system provided required attributes this class must store.",
    ),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_MUST: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Must,
    uuid: UUID_SCHEMA_ATTR_MUST,
    description: String::from(
        "A user modifiable list of required attributes this class must store.",
    ),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_SYSTEM_SUPPLEMENTS: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                name: Attribute::SystemSupplements,
                uuid: UUID_SCHEMA_ATTR_SYSTEMSUPPLEMENTS,
                description: String::from(
                    "A set of classes that this type supplements, where this class can't exist without their presence.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            }
});
pub static SCHEMA_ATTR_SUPPLEMENTS: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                name: Attribute::Supplements,
                uuid: UUID_SCHEMA_ATTR_SUPPLEMENTS,
                description: String::from(
                    "A set of user modifiable classes, where this determines that at least one other type must supplement this type",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            }
});
pub static SCHEMA_ATTR_SYSTEM_EXCLUDES: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::SystemExcludes,
        uuid: UUID_SCHEMA_ATTR_SYSTEMEXCLUDES,
        description: String::from(
            "A set of classes that are denied presence in connection to this class",
        ),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: false,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_EXCLUDES: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Excludes,
    uuid: UUID_SCHEMA_ATTR_EXCLUDES,
    description: String::from(
        "A set of user modifiable classes that are denied presence in connection to this class",
    ),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});

// SYSINFO attrs
// ACP attributes.
pub static SCHEMA_ATTR_ACP_ENABLE: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                name: Attribute::AcpEnable,
                uuid: UUID_SCHEMA_ATTR_ACP_ENABLE,
                description: String::from("A flag to determine if this ACP is active for application. True is enabled, and enforced. False is checked but not enforced."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Boolean,
            }
});

pub static SCHEMA_ATTR_ACP_RECEIVER: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpReceiver,
        uuid: UUID_SCHEMA_ATTR_ACP_RECEIVER,
        description: String::from("Who the ACP applies to, constraining or allowing operations."),
        multivalue: false,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::JsonFilter,
    });
pub static SCHEMA_ATTR_ACP_RECEIVER_GROUP: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpReceiverGroup,
        uuid: UUID_SCHEMA_ATTR_ACP_RECEIVER_GROUP,
        description: String::from("The group that receives this access control to allow access"),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::ReferenceUuid,
    });

pub static SCHEMA_ATTR_ACP_TARGET_SCOPE: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpTargetScope,
        uuid: UUID_SCHEMA_ATTR_ACP_TARGETSCOPE,
        description: String::from(
            "The effective targets of the ACP, e.g. what will be acted upon.",
        ),
        multivalue: false,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::JsonFilter,
    });
pub static SCHEMA_ATTR_ACP_SEARCH_ATTR: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpSearchAttr,
        uuid: UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR,
        description: String::from(
            "The attributes that may be viewed or searched by the receiver on targetscope.",
        ),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_ACP_CREATE_CLASS: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpCreateClass,
        uuid: UUID_SCHEMA_ATTR_ACP_CREATE_CLASS,
        description: String::from("The set of classes that can be created on a new entry."),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_ACP_CREATE_ATTR: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpCreateAttr,
        uuid: UUID_SCHEMA_ATTR_ACP_CREATE_ATTR,
        description: String::from("The set of attribute types that can be created on an entry."),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::Utf8StringInsensitive,
    });

pub static SCHEMA_ATTR_ACP_MODIFY_REMOVED_ATTR: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpModifyRemovedAttr,
        uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR,
        description: String::from(
            "The set of attribute types that could be removed or purged in a modification.",
        ),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_ACP_MODIFY_PRESENT_ATTR: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::AcpModifyPresentAttr,
        uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR,
        description: String::from(
            "The set of attribute types that could be added or asserted in a modification.",
        ),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_ACP_MODIFY_CLASS: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                name: Attribute::AcpModifyClass,
                uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS,
                description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            }
});
pub static SCHEMA_ATTR_ACP_MODIFY_PRESENT_CLASS: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                    name: Attribute::AcpModifyPresentClass,
                    uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENT_CLASS,
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: Replicated::True,
                    indexed: false,
                    syntax: SyntaxType::Utf8StringInsensitive,
                }
});
pub static SCHEMA_ATTR_ACP_MODIFY_REMOVE_CLASS: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                    name: Attribute::AcpModifyRemoveClass,
                    uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVE_CLASS,
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::remove operations on class."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: Replicated::True,
                    indexed: false,
                    syntax: SyntaxType::Utf8StringInsensitive,
                }
});
pub static SCHEMA_ATTR_ENTRY_MANAGED_BY: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::EntryManagedBy,
        uuid: UUID_SCHEMA_ATTR_ENTRY_MANAGED_BY,
        description: String::from(
            "A reference to a group that has access to manage the content of this entry.",
        ),
        multivalue: false,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::ReferenceUuid,
    });
// MO/Member
pub static SCHEMA_ATTR_MEMBER_OF: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::MemberOf,
    uuid: UUID_SCHEMA_ATTR_MEMBEROF,
    description: String::from("reverse group membership of the object"),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: true,
    syntax: SyntaxType::ReferenceUuid,
});
pub static SCHEMA_ATTR_DIRECT_MEMBER_OF: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::DirectMemberOf,
        uuid: UUID_SCHEMA_ATTR_DIRECTMEMBEROF,
        description: String::from("reverse direct group membership of the object"),
        multivalue: true,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: true,
        syntax: SyntaxType::ReferenceUuid,
    });
pub static SCHEMA_ATTR_RECYCLED_DIRECT_MEMBER_OF: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                name: Attribute::RecycledDirectMemberOf,
                uuid: UUID_SCHEMA_ATTR_RECYCLEDDIRECTMEMBEROF,
                description: String::from("recycled reverse direct group membership of the object to assist in revive operations."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                // Unlike DMO this must be replicated so that on a recycle event, these groups
                //  "at delete" are replicated to partners. This avoids us having to replicate
                // DMO which is very costly, while still retaining our ability to revive entries
                // and their group memberships as a best effort.
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            }
});
pub static SCHEMA_ATTR_MEMBER: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Member,
    uuid: UUID_SCHEMA_ATTR_MEMBER,
    description: String::from("List of members of the group"),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: true,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::ReferenceUuid,
});
pub static SCHEMA_ATTR_DYN_MEMBER: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::DynMember,
    uuid: UUID_SCHEMA_ATTR_DYNMEMBER,
    description: String::from("List of dynamic members of the group"),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: true,
    replicated: Replicated::False,
    indexed: true,
    syntax: SyntaxType::ReferenceUuid,
});

pub static SCHEMA_ATTR_REFERS: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Refers,
    uuid: UUID_SCHEMA_ATTR_REFERS,
    description: String::from("A reference to another object"),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::ReferenceUuid,
});

pub static SCHEMA_ATTR_CASCADE_DELETED: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
                name: Attribute::CascadeDeleted,
                uuid: UUID_SCHEMA_ATTR_CASCADE_DELETED,
                description: String::from("A marker attribute denoting that this entry was deleted by cascade when this UUID was deleted."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                // NOTE: This has to be Uuid so that referential integrity doesn't consider
                // this value in its operation.
                syntax: SyntaxType::Uuid,
            }
});

// Migration related
pub static SCHEMA_ATTR_VERSION: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Version,
    uuid: UUID_SCHEMA_ATTR_VERSION,
    description: String::from("The systems internal migration version for provided objects"),
    multivalue: false,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Uint32,
});
// Domain for sysinfo
pub static SCHEMA_ATTR_DOMAIN: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Domain,
    uuid: UUID_SCHEMA_ATTR_DOMAIN,
    description: String::from("A DNS Domain name entry."),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: true,
    syntax: SyntaxType::Utf8StringIname,
});
pub static SCHEMA_ATTR_CLAIM: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Claim,
    uuid: UUID_SCHEMA_ATTR_CLAIM,
    description: String::from("The string identifier of an extracted claim that can be filtered"),
    multivalue: true,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_SCOPE: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Scope,
    uuid: UUID_SCHEMA_ATTR_SCOPE,
    description: String::from("The string identifier of a permission scope in a session"),
    multivalue: true,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});

// External Scim Sync
pub static SCHEMA_ATTR_SYNC_EXTERNAL_ID: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::SyncExternalId,
        uuid: UUID_SCHEMA_ATTR_SYNC_EXTERNAL_ID,
        description: String::from(
            "An external string ID of an entry imported from a sync agreement",
        ),
        multivalue: false,
        unique: true,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_SYNC_PARENT_UUID: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::SyncParentUuid,
        uuid: UUID_SCHEMA_ATTR_SYNC_PARENT_UUID,
        description: String::from("The UUID of the parent sync agreement that created this entry."),
        multivalue: false,
        unique: false,
        phantom: false,
        sync_allowed: false,
        replicated: Replicated::True,
        indexed: true,
        syntax: SyntaxType::ReferenceUuid,
    });
pub static SCHEMA_ATTR_SYNC_CLASS: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::SyncClass,
    uuid: UUID_SCHEMA_ATTR_SYNC_CLASS,
    description: String::from("The set of classes requested by the sync client."),
    multivalue: true,
    unique: false,
    phantom: false,
    sync_allowed: false,
    replicated: Replicated::True,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});

pub static SCHEMA_ATTR_PASSWORD_IMPORT: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::PasswordImport,
        uuid: UUID_SCHEMA_ATTR_PASSWORD_IMPORT,
        description: String::from("An imported password hash from an external system."),
        multivalue: false,
        unique: false,
        phantom: true,
        sync_allowed: true,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::Utf8String,
    });

pub static SCHEMA_ATTR_UNIX_PASSWORD_IMPORT: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::UnixPasswordImport,
        uuid: UUID_SCHEMA_ATTR_UNIX_PASSWORD_IMPORT,
        description: String::from("An imported unix password hash from an external system."),
        multivalue: false,
        unique: false,
        phantom: true,
        sync_allowed: true,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::Utf8String,
    });

pub static SCHEMA_ATTR_TOTP_IMPORT: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::TotpImport,
    uuid: UUID_SCHEMA_ATTR_TOTP_IMPORT,
    description: String::from("An imported totp secret from an external system."),
    multivalue: true,
    unique: false,
    phantom: true,
    sync_allowed: true,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::TotpSecret,
});

// LDAP Masking Phantoms
pub static SCHEMA_ATTR_DN: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Dn,
    uuid: UUID_SCHEMA_ATTR_DN,
    description: String::from("An LDAP Compatible DN"),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_ENTRY_DN: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::EntryDn,
    uuid: UUID_SCHEMA_ATTR_ENTRYDN,
    description: String::from("An LDAP Compatible EntryDN"),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Utf8StringInsensitive,
});
pub static SCHEMA_ATTR_ENTRY_UUID: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::EntryUuid,
    uuid: UUID_SCHEMA_ATTR_ENTRYUUID,
    description: String::from("An LDAP Compatible entryUUID"),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Uuid,
});
pub static SCHEMA_ATTR_OBJECT_CLASS: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::ObjectClass,
        uuid: UUID_SCHEMA_ATTR_OBJECTCLASS,
        description: String::from("An LDAP Compatible objectClass"),
        multivalue: true,
        unique: false,
        phantom: true,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::Utf8StringInsensitive,
    });
pub static SCHEMA_ATTR_CN: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Cn,
    uuid: UUID_SCHEMA_ATTR_CN,
    description: String::from("An LDAP Compatible objectClass"),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Utf8StringIname,
});
pub static SCHEMA_ATTR_LDAP_KEYS: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::LdapKeys, // keys
    uuid: UUID_SCHEMA_ATTR_KEYS,
    description: String::from("An LDAP Compatible keys (ssh)"),
    multivalue: true,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::SshKey,
});
pub static SCHEMA_ATTR_LDAP_SSH_PUBLIC_KEYS: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::LdapSshPublicKey,
        uuid: UUID_SCHEMA_ATTR_SSHPUBLICKEY,
        description: String::from("An LDAP Compatible sshPublicKey"),
        multivalue: true,
        unique: false,
        phantom: true,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::SshKey,
    });
pub static SCHEMA_ATTR_EMAIL: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Email,
    uuid: UUID_SCHEMA_ATTR_EMAIL,
    description: String::from("An LDAP Compatible email"),
    multivalue: true,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::EmailAddress,
});
pub static SCHEMA_ATTR_EMAIL_PRIMARY: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::EmailPrimary,
        uuid: UUID_SCHEMA_ATTR_EMAILPRIMARY,
        description: String::from("An LDAP Compatible primary email"),
        multivalue: false,
        unique: false,
        phantom: true,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::EmailAddress,
    });
pub static SCHEMA_ATTR_EMAIL_ALTERNATIVE: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::EmailAlternative,
        uuid: UUID_SCHEMA_ATTR_EMAILALTERNATIVE,
        description: String::from("An LDAP Compatible alternative email"),
        multivalue: false,
        unique: false,
        phantom: true,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::EmailAddress,
    });
pub static SCHEMA_ATTR_LDAP_EMAIL_ADDRESS: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::LdapEmailAddress,
        uuid: UUID_SCHEMA_ATTR_EMAILADDRESS,
        description: String::from("An LDAP Compatible emailAddress"),
        multivalue: true,
        unique: false,
        phantom: true,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::EmailAddress,
    });
pub static SCHEMA_ATTR_GECOS: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Gecos,
    uuid: UUID_SCHEMA_ATTR_GECOS,
    description: String::from("An LDAP Compatible gecos."),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Utf8String,
});
pub static SCHEMA_ATTR_UID: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::Uid,
    uuid: UUID_SCHEMA_ATTR_UID,
    description: String::from("An LDAP Compatible uid."),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Utf8String,
});
pub static SCHEMA_ATTR_UID_NUMBER: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::UidNumber,
    uuid: UUID_SCHEMA_ATTR_UIDNUMBER,
    description: String::from("An LDAP Compatible uidNumber."),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Uint32,
});
pub static SCHEMA_ATTR_SUDO_HOST: LazyLock<SchemaAttribute> = LazyLock::new(|| SchemaAttribute {
    name: Attribute::SudoHost,
    uuid: UUID_SCHEMA_ATTR_SUDOHOST,
    description: String::from("An LDAP Compatible sudohost."),
    multivalue: false,
    unique: false,
    phantom: true,
    sync_allowed: false,
    replicated: Replicated::False,
    indexed: false,
    syntax: SyntaxType::Utf8String,
});
pub static SCHEMA_ATTR_HOME_DIRECTORY: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        name: Attribute::HomeDirectory,
        uuid: UUID_SCHEMA_ATTR_HOME_DIRECTORY,
        description: String::from("An LDAP Compatible homeDirectory."),
        multivalue: false,
        unique: false,
        phantom: true,
        sync_allowed: false,
        replicated: Replicated::False,
        indexed: false,
        syntax: SyntaxType::Utf8String,
    });
// end LDAP masking phantoms

// THIS IS FOR SYSTEM CRITICAL INTERNAL SCHEMA ONLY

// =================================================================

pub static SCHEMA_CLASS_ATTRIBUTE_TYPE: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    name: EntryClass::AttributeType.into(),
    uuid: UUID_SCHEMA_CLASS_ATTRIBUTETYPE,
    description: String::from("Definition of a schema attribute"),
    systemmay: vec![
        Attribute::Replicated,
        Attribute::Phantom,
        Attribute::SyncAllowed,
        Attribute::Index,
        Attribute::Indexed,
    ],
    systemmust: vec![
        Attribute::Class,
        Attribute::AttributeName,
        Attribute::MultiValue,
        Attribute::Unique,
        Attribute::Syntax,
        Attribute::Description,
    ],
    systemexcludes: vec![EntryClass::ClassType.into()],
    ..Default::default()
});
pub static SCHEMA_CLASS_CLASS_TYPE: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    name: EntryClass::ClassType.into(),
    uuid: UUID_SCHEMA_CLASS_CLASSTYPE,
    description: String::from("Definition of a schema classtype"),
    systemmay: vec![
        Attribute::SyncAllowed,
        Attribute::SystemMay,
        Attribute::May,
        Attribute::SystemMust,
        Attribute::Must,
        Attribute::SystemSupplements,
        Attribute::Supplements,
        Attribute::SystemExcludes,
        Attribute::Excludes,
    ],
    systemmust: vec![
        Attribute::Class,
        Attribute::ClassName,
        Attribute::Description,
    ],
    systemexcludes: vec![Attribute::AttributeType.into()],
    ..Default::default()
});
pub static SCHEMA_CLASS_OBJECT: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    name: EntryClass::Object.into(),
    uuid: UUID_SCHEMA_CLASS_OBJECT,
    description: String::from("A system created class that all objects must contain"),
    systemmay: vec![
        Attribute::Description,
        Attribute::EntryManagedBy,
        Attribute::MemberOf,
        Attribute::DirectMemberOf,
    ],
    systemmust: vec![
        Attribute::Class,
        Attribute::Uuid,
        Attribute::LastModifiedCid,
        Attribute::CreatedAtCid,
    ],
    ..Default::default()
});
pub static SCHEMA_CLASS_BUILTIN: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    name: EntryClass::Builtin.into(),
    uuid: UUID_SCHEMA_CLASS_BUILTIN,
    description: String::from("A marker class denoting builtin entries"),
    ..Default::default()
});
pub static SCHEMA_CLASS_MEMBER_OF: LazyLock<SchemaClass> = LazyLock::new(|| {
    SchemaClass {
                name: EntryClass::MemberOf.into(),
                uuid: UUID_SCHEMA_CLASS_MEMBEROF,
                description: String::from(
                    "Class that is dynamically added to recipients of memberof or directmemberof. TO BE REMOVED.",
                ),
                ..Default::default()
            }
});
pub static SCHEMA_CLASS_EXTENSIBLE_OBJECT: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    name: EntryClass::ExtensibleObject.into(),
    uuid: UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT,
    description: String::from("A class type that has green hair and turns off all rules ..."),
    ..Default::default()
});
/* These two classes are core to the entry lifecycle for recycling and tombstoning */
pub static SCHEMA_CLASS_RECYCLED: LazyLock<SchemaClass> = LazyLock::new(|| {
    SchemaClass {
                    name: EntryClass::Recycled.into(),
                    uuid: UUID_SCHEMA_CLASS_RECYCLED,
                    description: String::from("An object that has been deleted, but still recoverable via the revive operation. Recycled objects are not modifiable, only revivable."),
                    systemmay: vec![Attribute::RecycledDirectMemberOf, Attribute::CascadeDeleted],
                    .. Default::default()
                }
});
pub static SCHEMA_CLASS_TOMBSTONE: LazyLock<SchemaClass> = LazyLock::new(|| {
    SchemaClass {
                    name: EntryClass::Tombstone.into(),
                    uuid: UUID_SCHEMA_CLASS_TOMBSTONE,
                    description: String::from("An object that is purged from the recycle bin. This is a system internal state. Tombstones have no attributes beside UUID."),
                    systemmust: vec![
                        Attribute::Class,
                        Attribute::Uuid,
                    ],
                    .. Default::default()
                }
});
pub static SCHEMA_CLASS_CONFLICT: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    name: EntryClass::Conflict.into(),
    uuid: UUID_SCHEMA_CLASS_CONFLICT,
    description: String::from("An entry representing conflicts that occurred during replication"),
    systemmust: vec![Attribute::SourceUuid],
    systemsupplements: vec![EntryClass::Recycled.into()],
    ..Default::default()
});
// sysinfo
pub static SCHEMA_CLASS_SYSTEM_INFO: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    name: EntryClass::SystemInfo.into(),
    uuid: UUID_SCHEMA_CLASS_SYSTEM_INFO,
    description: String::from("System metadata object class"),
    systemmust: vec![Attribute::Version],
    ..Default::default()
});
// ACP
pub static SCHEMA_CLASS_ACCESS_CONTROL_SEARCH: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlSearch.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH,
        description: String::from("System Access Control Search Class"),
        systemmust: vec![Attribute::AcpSearchAttr],
        ..Default::default()
    });
pub static SCHEMA_CLASS_ACCESS_CONTROL_DELETE: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlDelete.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE,
        description: String::from("System Access Control DELETE Class"),
        ..Default::default()
    });
pub static SCHEMA_CLASS_ACCESS_CONTROL_MODIFY: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlModify.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY,
        description: String::from("System Access Control Modify Class"),
        systemmay: vec![
            Attribute::AcpModifyRemovedAttr,
            Attribute::AcpModifyPresentAttr,
            Attribute::AcpModifyClass,
            Attribute::AcpModifyPresentClass,
            Attribute::AcpModifyRemoveClass,
        ],
        ..Default::default()
    });
pub static SCHEMA_CLASS_ACCESS_CONTROL_CREATE: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlCreate.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE,
        description: String::from("System Access Control Create Class"),
        systemmay: vec![Attribute::AcpCreateClass, Attribute::AcpCreateAttr],
        ..Default::default()
    });
pub static SCHEMA_CLASS_ACCESS_CONTROL_PROFILE: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlProfile.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE,
        description: String::from("System Access Control Profile Class"),
        systemmay: vec![Attribute::AcpEnable, Attribute::Description],
        systemmust: vec![Attribute::Name],
        systemsupplements: vec![
            EntryClass::AccessControlSearch.into(),
            EntryClass::AccessControlDelete.into(),
            EntryClass::AccessControlModify.into(),
            EntryClass::AccessControlCreate.into(),
        ],
        ..Default::default()
    });
pub static SCHEMA_CLASS_ACCESS_CONTROL_RECEIVER_ENTRY_MANAGER: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlReceiverEntryManager.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_RECEIVER_ENTRY_MANAGER,
        description: String::from("System Access Control Profile Receiver - Entry Manager"),
        systemexcludes: vec![EntryClass::AccessControlReceiverGroup.into()],
        systemsupplements: vec![EntryClass::AccessControlProfile.into()],
        ..Default::default()
    });
pub static SCHEMA_CLASS_ACCESS_CONTROL_RECEIVER_GROUP: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlReceiverGroup.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_RECEIVER_GROUP,
        description: String::from("System Access Control Profile Receiver - Group"),
        systemmay: vec![Attribute::AcpReceiver],
        systemmust: vec![Attribute::AcpReceiverGroup],
        systemsupplements: vec![EntryClass::AccessControlProfile.into()],
        systemexcludes: vec![EntryClass::AccessControlReceiverEntryManager.into()],
        ..Default::default()
    });
pub static SCHEMA_CLASS_ACCESS_COUNTROL_TARGET_SCOPE: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        name: EntryClass::AccessControlTargetScope.into(),
        uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_TARGET_SCOPE,
        description: String::from("System Access Control Profile Target - Scope"),
        systemmust: vec![Attribute::AcpTargetScope],
        systemsupplements: vec![EntryClass::AccessControlProfile.into()],
        ..Default::default()
    });

// System attrs
pub static SCHEMA_CLASS_SYSTEM: LazyLock<SchemaClass> = LazyLock::new(|| {
    SchemaClass {
                name: EntryClass::System.into(),
                uuid: UUID_SCHEMA_CLASS_SYSTEM,
                description: String::from("A class denoting that a type is system generated and protected. It has special internal behaviour."),
                .. Default::default()
            }
});
pub static SCHEMA_CLASS_SYNC_OBJECT: LazyLock<SchemaClass> = LazyLock::new(|| {
    SchemaClass {
                name: EntryClass::SyncObject.into(),
                uuid: UUID_SCHEMA_CLASS_SYNC_OBJECT,
                description: String::from("A class denoting that an entry is synchronised from an external source. This entry may not be modifiable."),
                systemmust: vec![
                    Attribute::SyncParentUuid
                ],
                systemmay: vec![
                    Attribute::SyncExternalId,
                    Attribute::SyncClass,
                ],
                .. Default::default()
            }
});
