use crate::prelude::{Attribute, EntryClass};
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// These entry classes may be affected by migrations. All protection rules still
/// apply.
pub static MIGRATION_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::Object,
        EntryClass::MemberOf,
        EntryClass::DomainInfo,
        EntryClass::OAuth2ResourceServer,
        EntryClass::OAuth2ResourceServerBasic,
        EntryClass::OAuth2ResourceServerPublic,
        EntryClass::Account,
        EntryClass::Person,
        EntryClass::PosixAccount,
        EntryClass::Group,
        EntryClass::DynGroup,
        EntryClass::AccountPolicy,
        EntryClass::PosixGroup,
        EntryClass::ServiceAccount,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

pub static MIGRATION_IGNORE_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::KeyObject,
        EntryClass::KeyObjectInternal,
        EntryClass::KeyObjectHkdfS256,
        EntryClass::KeyObjectJwtEs256,
        EntryClass::KeyObjectJwtHs256,
        EntryClass::KeyObjectJwtRs256,
        EntryClass::KeyObjectJweA128GCM,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

pub fn migration_entry_attrs(
    classes: &BTreeSet<String>,
) -> (BTreeSet<Attribute>, BTreeSet<&'static str>) {
    let mut allow_attrs = BTreeSet::default();
    let mut allow_cls: BTreeSet<&'static str> = BTreeSet::default();

    // Base attributes to always allow
    allow_attrs.extend([Attribute::Class, Attribute::Uuid]);

    if classes.contains(EntryClass::DomainInfo.into()) {
        allow_attrs.extend([
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::DomainDisplayName,
        ]);
    }

    if classes.contains(EntryClass::Group.into()) {
        allow_cls.clear();
        allow_cls.extend([
            Into::<&'static str>::into(EntryClass::Group),
            Into::<&'static str>::into(EntryClass::AccountPolicy),
            Into::<&'static str>::into(EntryClass::PosixGroup),
        ]);
        allow_attrs.extend([Attribute::Member, Attribute::Name, Attribute::Description])
    }

    if classes.contains(EntryClass::Person.into()) {
        allow_cls.clear();
        allow_cls.extend([
            Into::<&'static str>::into(EntryClass::Person),
            Into::<&'static str>::into(EntryClass::Account),
            Into::<&'static str>::into(EntryClass::PosixAccount),
        ]);
        allow_attrs.extend([
            Attribute::Name,
            Attribute::LegalName,
            Attribute::Mail,
            Attribute::SshPublicKey,
            Attribute::Description,
        ])
    }

    if classes.contains(EntryClass::ServiceAccount.into()) {
        allow_cls.clear();
        allow_cls.extend([
            Into::<&'static str>::into(EntryClass::Account),
            Into::<&'static str>::into(EntryClass::ServiceAccount),
        ]);
        allow_attrs.extend([
            Attribute::Name,
            Attribute::Mail,
            Attribute::SshPublicKey,
            Attribute::Description,
        ])
    }

    if classes.contains(EntryClass::AccountPolicy.into()) {
        allow_attrs.extend([
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
            Attribute::AllowPrimaryCredFallback,
        ]);
    }

    if classes.contains(EntryClass::OAuth2ResourceServer.into()) {
        allow_cls.clear();
        allow_cls.extend([
            Into::<&'static str>::into(EntryClass::OAuth2ResourceServer),
            Into::<&'static str>::into(EntryClass::OAuth2ResourceServerBasic),
            Into::<&'static str>::into(EntryClass::OAuth2ResourceServerPublic),
        ]);
        allow_attrs.extend([
            Attribute::Name,
            Attribute::Description,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2RsClaimMap,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2ConsentPromptEnable,
        ])
    }

    (allow_attrs, allow_cls)
}
