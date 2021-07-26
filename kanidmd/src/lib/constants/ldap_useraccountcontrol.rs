//! Flags and byte values for the LDAP UserAccountControl Attribute
//!
//! Ref: <https://ldapwiki.com/wiki/User-Account-Control%20Attribute%20Values>

/// This attribute value can be zero or a combination of one or more of the following values.
///
/// You cannot set some of the values on a user or computer object because these values can be set or reset only by the directory service.
///
/// The flags are cumulative. To disable a user's account, set the UserAccountControl attribute to 514 (2 + 512).
///
/// Since User-Account-Control-Attribute is a constructed attribute, it cannot be used in an LDAP search filter.
#[derive(Default)]
pub struct LdapUac {
    pub value: u32,
}

impl LdapUac {
    pub fn new() -> Self {
        LdapUac { value: 0 }
    }

    pub fn flag_disable(self) -> Self {
        LdapUac {
            value: self.value + LdapUacFlag::AccountDisable.to_uint(),
        }
    }

    pub fn flag_normal_account(self) -> Self {
        LdapUac {
            value: self.value + LdapUacFlag::NormalAccount.to_uint(),
        }
    }

    pub fn addflag(self, newflag: LdapUacFlag) -> Self {
        LdapUac {
            value: self.value + newflag.to_uint(),
        }
    }
}

pub enum LdapUacFlag {
    Script,                       // The logon script is executed.
    AccountDisable,               // The user account is disabled.
    HomedirRequired,              // The home directory is required.
    Lockout, // The account is currently locked from Intruder Detection. This value can be cleared to unlock a previously locked account.
    PasswdNotRequired, // No password is required.
    PasswordCantChange, // The user cannot change the password. Note: You cannot assign the permission settings of PasswordCantChange by directly modifying the UserAccountControl attribute. For more information and a code example that shows how to prevent a user from changing the password, see User Cannot Change Password.
    EncryptedTextPasswordAllowed, // The user can send an encrypted password.
    TemplDuplicateAccount, // This is an account for users whose primary account is in another AD DOMAIN. This account provides user access to this AD DOMAIN, but not to any AD DOMAIN that trusts this AD DOMAIN. Also known as a local user account.
    NormalAccount,         // This is a default account type that represents a typical user.
    InterDomainTrustAccount, // This is a permit to trust account for a system AD DOMAIN that trusts other AD DOMAIN.
    WorkstationTrustAccount, // This is a computer account for a computer that is a member of this AD DOMAIN.
    ServerTrustAccount, // This is a computer account for a system backup Domain Controller that is a member of this AD DOMAIN.
    DontExpirePassword, // The password for this account will never expire.
    MnsLogonAccount,    // This is an MNS logon account.
    SmartcardRequired,  // The user must log on using a Smart Card.
    TrustedForDelegation, // The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service.
    NotDelgated, // The security context of the user will NOT be delegated to a service even if the service account is set as trusted for Kerberos delegation.
    UseDesKeyOnly, // Restrict this UserPrincipalName to use only Data Encryption Standard (DES) encryption types for keys.
    DontRequirePreAuth, // This account does not require Kerberos Pre-Authentication for logon.
    ErrorPasswordExpired, // The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the AD DOMAIN policy.
    TrustedToAuthnForDelegation, // The account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled SHOULD be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate as that user to other remote servers on the network.
    PartialSecretsAccount, // (Windows Server 2008/Windows Server 2008 R2) The account is a Read-Only Domain Controller (RODC). This is a security-sensitive setting. Removing this setting from an RODC compromises security on that server.
    UserUseAesKeys, // Restrict this UserPrincipalName to use only Advanced Encryption Standard (AES) encryption types for keys. This bit is ignored by Windows Client and Windows Servers.
}

impl LdapUacFlag {
    fn to_uint(&self) -> u32 {
        match self {
            LdapUacFlag::Script => 1,
            LdapUacFlag::AccountDisable => 2,
            LdapUacFlag::HomedirRequired => 8,
            LdapUacFlag::Lockout => 16,
            LdapUacFlag::PasswdNotRequired => 32,
            LdapUacFlag::PasswordCantChange => 64,
            LdapUacFlag::EncryptedTextPasswordAllowed => 128,
            LdapUacFlag::TemplDuplicateAccount => 256,
            LdapUacFlag::NormalAccount => 512,
            LdapUacFlag::InterDomainTrustAccount => 2048,
            LdapUacFlag::WorkstationTrustAccount => 4096,
            LdapUacFlag::ServerTrustAccount => 8192,
            LdapUacFlag::DontExpirePassword => 65536,
            LdapUacFlag::MnsLogonAccount => 131072,
            LdapUacFlag::SmartcardRequired => 262144,
            LdapUacFlag::TrustedForDelegation => 524288,
            LdapUacFlag::NotDelgated => 1048576,
            LdapUacFlag::UseDesKeyOnly => 2097152,
            LdapUacFlag::DontRequirePreAuth => 4194304,
            LdapUacFlag::ErrorPasswordExpired => 8388608,
            LdapUacFlag::TrustedToAuthnForDelegation => 16777216,
            LdapUacFlag::PartialSecretsAccount => 67108864,
            LdapUacFlag::UserUseAesKeys => 2147483648,
        }
    }
}

mod tests {
    #[test]
    fn test_ldap_uac_adding_flags() {
        use crate::constants::ldap_useraccountcontrol::{LdapUac, LdapUacFlag};

        let testuac = LdapUac::new();
        assert_eq!(0, testuac.value);

        let testuac = testuac.addflag(LdapUacFlag::Lockout);
        assert_eq!(16, testuac.value);
    }

    #[test]
    fn test_ldap_uac_fromstring() {
        use crate::constants::ldap_useraccountcontrol::LdapUacFlag;
        let testuac = LdapUacFlag::UserUseAesKeys;
        assert_eq!(testuac.to_uint(), 2147483648);
    }
    #[test]
    fn test_ldap_uac_normalaccount() {
        use crate::constants::ldap_useraccountcontrol::LdapUac;
        let user = LdapUac::new().flag_normal_account();
        assert_eq!(user.value, 512);
        let user = LdapUac::new().flag_normal_account().flag_disable();
        assert_eq!(user.value, 514);
    }
}
