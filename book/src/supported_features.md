# Supported Features

This is a list of supported features and standards within Kanidm.

# Authorisation

- [Role Based Access Control](https://csrc.nist.gov/pubs/conference/1992/10/13/rolebased-access-controls/final)
- [NIST Digital Identity Guidelines](https://csrc.nist.gov/pubs/sp/800/63/b/upd2/final)

# Cryptography

- Password Storage
  - [RFC9106 - Argon2ID](https://datatracker.ietf.org/doc/rfc9106/)
  - [TCG TPM Credential Binding (HMAC)](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [RFC6238 Time Based One Time Password](https://www.rfc-editor.org/rfc/rfc6238)
- [RFC7519 JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC7516 JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516.html)

# Data Import

- [RFC4533 LDAP Content Synchronisation](https://datatracker.ietf.org/doc/html/rfc4533)
  - [RFC4519 LDAP Schema](https://www.rfc-editor.org/rfc/rfc4519)
  - FreeIPA User Schema
- [RFC7644 SCIM Bulk Data Import](https://www.rfc-editor.org/rfc/rfc7644)
  - NOTE: SCIM is only supported for synchronisation from another IDP at this time.

# Database

- [ACID Compliance](https://dl.acm.org/doi/10.1145/289.291)

# LDAP

- [RFC4511 LDAP (read-only)](https://www.rfc-editor.org/rfc/rfc4511)
  - bind (simple)
  - search
  - filter
  - whoami
  - compare
- LDAPS (LDAP over TLS)

# OAuth2 / OpenID Connect

- [RFC6749 OAuth 2.0 Authorisation Framework](https://www.rfc-editor.org/rfc/rfc6749)
  - Authorisation Code Grant
  - Client Credentials Grant
  - RBAC scope mapping
- [RFC6819 OAauth 2.0 Threat Model and Security Considerations](https://www.rfc-editor.org/rfc/rfc6819)
- [RFC7009 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [RFC7662 OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC7636 Proof Key for Code Exchange (SHA256 Only)](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC8414 OAuth 2.0 Authorisation Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC9068 OAuth 2.0 JWT Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  - RBAC claim and scope mapping
  - PII scope claim requests
  - ES256 `id_token` signatures
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

# RADIUS

- [MSCHAPv2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-chap/4740bf05-db7e-4542-998f-5a4478768438)
- [EAP TLS (client certificate authentication)](https://wiki.freeradius.org/protocol/EAP#eap-sub-types_eap-tls)

# Replication

- [Strong Eventual Consistency](https://en.wikipedia.org/wiki/Eventual_consistency)

# Unix Client

- PAM/nsswitch client authentication

# Webauthn

- [Webauthn (level 3)](https://www.w3.org/TR/webauthn-3/)
- [FIDO MDS Attestation](https://fidoalliance.org/metadata/)
