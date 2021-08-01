//! Constants for the LDAP server

use std::convert::From;
use std::ops::BitAnd;

/// Flags and byte values for the LDAP UserAccountControl Attribute.
/// This attribute value can be zero or a combination of one or more of the following values.
///
/// The flags are cumulative. To disable a user's account, set the attribute to [LdapUacFlag::AccountDisable] & [LdapUacFlag::NormalAccount]  (2 + 512).
///
/// Since User-Account-Control-Attribute is a constructed attribute, it cannot be used in an LDAP search filter.
///
/// - Field Ref: <https://ldapwiki.com/wiki/User-Account-Control%20Attribute>
/// - Values Ref: <https://ldapwiki.com/wiki/User-Account-Control%20Attribute%20Values>

#[derive(Debug)]
/// Flag values for UserAccountControl. AND (&) them together to get a flag value to return in LDAP responses
pub enum LdapUacFlag {
    /// If you provide it a wrong value, you get back InvalidFlag which equates to 0;
    InvalidFlag,
    /// The logon script is executed.
    Script,
    /// The user account is disabled.
    AccountDisable,
    /// The home directory is required.
    HomedirRequired,
    /// The account is currently locked from Intruder Detection. This value can be cleared to unlock a previously locked account.
    Lockout,
    ///  No password is required.
    PasswdNotRequired,
    ///  The user cannot change the password. Note: You cannot assign the permission settings of PasswordCantChange by directly modifying the UserAccountControl attribute. For more information and a code example that shows how to prevent a user from changing the password, see User Cannot Change Password.
    PasswordCantChange,
    ///  The user can send an encrypted password.
    EncryptedTextPasswordAllowed,
    ///  This is an account for users whose primary account is in another AD DOMAIN. This account provides user access to this AD DOMAIN, but not to any AD DOMAIN that trusts this AD DOMAIN. Also known as a local user account.
    TemplDuplicateAccount,
    /// This is a default account type that represents a typical user.
    NormalAccount,
    ///  This is a permit to trust account for a system AD DOMAIN that trusts other AD DOMAIN.
    InterDomainTrustAccount,
    ///  This is a computer account for a computer that is a member of this AD DOMAIN.
    WorkstationTrustAccount,
    ///  This is a computer account for a system backup Domain Controller that is a member of this AD DOMAIN.
    ServerTrustAccount,
    ///  The password for this account will never expire.
    DontExpirePassword,
    ///  This is an MNS logon account.
    MnsLogonAccount,
    ///  The user must log on using a Smart Card.
    SmartcardRequired,
    ///  The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service.
    TrustedForDelegation,
    ///  The security context of the user will NOT be delegated to a service even if the service account is set as trusted for Kerberos delegation.
    NotDelgated,
    ///  Restrict this UserPrincipalName to use only Data Encryption Standard (DES) encryption types for keys.
    UseDesKeyOnly,
    ///  This account does not require Kerberos Pre-Authentication for logon.
    DontRequirePreAuth,
    ///  The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the AD DOMAIN policy.
    ErrorPasswordExpired,
    ///  The account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled SHOULD be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate as that user to other remote servers on the network.
    TrustedToAuthnForDelegation,
    ///  (Windows Server 2008/Windows Server 2008 R2) The account is a Read-Only Domain Controller (RODC). This is a security-sensitive setting. Removing this setting from an RODC compromises security on that server.
    PartialSecretsAccount,
    ///  Restrict this UserPrincipalName to use only Advanced Encryption Standard (AES) encryption types for keys. This bit is ignored by Windows Client and Windows Servers.
    UserUseAesKeys,
}

impl From<LdapUacFlag> for u32 {
    /// Get the uint type of the flag, so you can add them together.
    ///
    /// ```
    /// use kanidm::constants::ldap::LdapUacFlag;
    /// let testuac: u32 = LdapUacFlag::UserUseAesKeys.into();
    /// assert_eq!(testuac, 2147483648);
    /// ```
    fn from(flag: LdapUacFlag) -> u32 {
        match flag {
            LdapUacFlag::InvalidFlag => 0,
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

impl BitAnd for LdapUacFlag {
    type Output = u32;
    /// Implements the & function for [LdapUacFlag]
    ///
    /// ```
    /// use kanidm::constants::ldap::LdapUacFlag;
    /// let testval: u32 = LdapUacFlag::Lockout & LdapUacFlag::PasswdNotRequired;
    /// assert_eq!(testval, 48);
    /// ```
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn bitand(self, rhs: Self) -> u32 {
        // rhs is the "right-hand side" of the expression `a & b`
        let lhs: u32 = self.into();
        let rhs: u32 = rhs.into();
        lhs + rhs
    }
}

impl BitAnd<u32> for LdapUacFlag {
    type Output = u32;

    /// Implements the & function for [LdapUacFlag]
    ///
    /// ```
    /// use kanidm::constants::ldap::LdapUacFlag;
    /// let testval: u32 = LdapUacFlag::Lockout & LdapUacFlag::PasswdNotRequired;
    /// assert_eq!(testval, 48);
    /// ```
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn bitand(self, rhs: u32) -> u32 {
        // rhs is the "right-hand side" of the expression `a & b`
        let lhs: u32 = self.into();
        let rhs: u32 = rhs;
        lhs + rhs
    }
}

impl From<&LdapUacFlag> for u32 {
    fn from(flag: &LdapUacFlag) -> u32 {
        let result: u32 = flag.into();
        result
    }
}

impl From<u32> for LdapUacFlag {
    /// Returns a LdapUacFlag if you give it a u32
    ///
    /// ```
    /// use kanidm::constants::ldap::LdapUacFlag;
    /// let lhs: u32 = LdapUacFlag::NotDelgated.into();
    /// let rhs: u32 = LdapUacFlag::from(1048576).into();
    ///
    /// assert_eq!(lhs, rhs);
    /// ```
    fn from(number: u32) -> Self {
        match number {
            1 => LdapUacFlag::Script,
            2 => LdapUacFlag::AccountDisable,
            8 => LdapUacFlag::HomedirRequired,
            16 => LdapUacFlag::Lockout,
            32 => LdapUacFlag::PasswdNotRequired,
            64 => LdapUacFlag::PasswordCantChange,
            128 => LdapUacFlag::EncryptedTextPasswordAllowed,
            256 => LdapUacFlag::TemplDuplicateAccount,
            512 => LdapUacFlag::NormalAccount,
            2048 => LdapUacFlag::InterDomainTrustAccount,
            4096 => LdapUacFlag::WorkstationTrustAccount,
            8192 => LdapUacFlag::ServerTrustAccount,
            65536 => LdapUacFlag::DontExpirePassword,
            131072 => LdapUacFlag::MnsLogonAccount,
            262144 => LdapUacFlag::SmartcardRequired,
            524288 => LdapUacFlag::TrustedForDelegation,
            1048576 => LdapUacFlag::NotDelgated,
            2097152 => LdapUacFlag::UseDesKeyOnly,
            4194304 => LdapUacFlag::DontRequirePreAuth,
            8388608 => LdapUacFlag::ErrorPasswordExpired,
            16777216 => LdapUacFlag::TrustedToAuthnForDelegation,
            67108864 => LdapUacFlag::PartialSecretsAccount,
            2147483648 => LdapUacFlag::UserUseAesKeys,
            _ => {
                eprintln!("Invalid flag int provided, returning InvalidFlag");
                LdapUacFlag::InvalidFlag
            }
        }
    }
}
