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
///
/// ```
/// use kanidm::constants::ldap::LdapUacFlag;
/// let testval: u32 = LdapUacFlag::Lockout & LdapUacFlag::PasswdNotRequired;
/// assert_eq!(testval, 48);
/// ```

#[derive(PartialEq, Debug, Eq, Hash, Copy, Clone)]
#[repr(u32)]
/// Flag values for UserAccountControl. AND (&) them together to get a flag value to return in LDAP responses
pub enum LdapUacFlag {
    /// If you provide it a wrong value, you get back InvalidFlag which equates to 0;
    InvalidFlag = 0,
    /// The logon script is executed.
    Script = 1,
    /// The user account is disabled.
    AccountDisable = 2,
    /// The home directory is required.
    HomedirRequired = 8,
    /// The account is currently locked from Intruder Detection. This value can be cleared to unlock a previously locked account.
    Lockout = 16,
    ///  No password is required.
    PasswdNotRequired = 32,
    ///  The user cannot change the password. Note: You cannot assign the permission settings of PasswordCantChange by directly modifying the UserAccountControl attribute. For more information and a code example that shows how to prevent a user from changing the password, see User Cannot Change Password.
    PasswordCantChange = 64,
    ///  The user can send an encrypted password.
    EncryptedTextPasswordAllowed = 128,
    ///  This is an account for users whose primary account is in another AD DOMAIN. This account provides user access to this AD DOMAIN, but not to any AD DOMAIN that trusts this AD DOMAIN. Also known as a local user account.
    TemplDuplicateAccount = 256,
    /// This is a default account type that represents a typical user.
    NormalAccount = 512,
    ///  This is a permit to trust account for a system AD DOMAIN that trusts other AD DOMAIN.
    InterDomainTrustAccount = 2048,
    ///  This is a computer account for a computer that is a member of this AD DOMAIN.
    WorkstationTrustAccount = 4096,
    ///  This is a computer account for a system backup Domain Controller that is a member of this AD DOMAIN.
    ServerTrustAccount = 8192,
    ///  The password for this account will never expire.
    DontExpirePassword = 65536,
    ///  This is an MNS logon account.
    MnsLogonAccount = 131072,
    ///  The user must log on using a Smart Card.
    SmartcardRequired = 262144,
    ///  The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service.
    TrustedForDelegation = 524288,
    ///  The security context of the user will NOT be delegated to a service even if the service account is set as trusted for Kerberos delegation.
    NotDelgated = 1048576,
    ///  Restrict this UserPrincipalName to use only Data Encryption Standard (DES) encryption types for keys.
    UseDesKeyOnly = 2097152,
    ///  This account does not require Kerberos Pre-Authentication for logon.
    DontRequirePreAuth = 4194304,
    ///  The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the AD DOMAIN policy.
    ErrorPasswordExpired = 8388608,
    ///  The account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled SHOULD be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate as that user to other remote servers on the network.
    TrustedToAuthnForDelegation = 16777216,
    ///  (Windows Server 2008/Windows Server 2008 R2) The account is a Read-Only Domain Controller (RODC). This is a security-sensitive setting. Removing this setting from an RODC compromises security on that server.
    PartialSecretsAccount = 67108864,
    ///  Restrict this UserPrincipalName to use only Advanced Encryption Standard (AES) encryption types for keys. This bit is ignored by Windows Client and Windows Servers.
    UserUseAesKeys = 2147483648,
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
        flag as u32
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
        let lhs = self as u32;
        let rhs = rhs as u32;
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
        let lhs = self as u32;
        let rhs = rhs as u32;
        lhs + rhs
    }
}

impl From<&LdapUacFlag> for u32 {
    fn from(flag: &LdapUacFlag) -> u32 {
        flag.to_owned() as u32
    }
}
