# Identifiable Secrets

Kanidm tokens should have a unique pattern, making them easy to recognize. This is crucial for security systems that aim to prevent incorrect credential storage. Without a distinct pattern, like with bare JWTs that look like any base64-encoded data, we risk false alarms.

## The Kanidm pattern

> **RFC Discussion here**
>
> Another option could be to use the pattern `kanidm_<CREDENTIAL>`. This way, users can figure out what kind of token they have.

```text
kanidm_<TYPE>_<CREDENTIAL>
```
Where:

- `<TYPE>` is the type of the credential, such as OAuth secret, UAT, and so on. Examples include:
  - uat
  - ors
  - unx
- `<CREDENTIAL>` is the actual credential.

We can make this compatible with current systems by checking if the submitted token starts with `kanidm_\w+_`. If it does, we remove that part and continue with validation.

Regular expressions should NOT be used. Credentials are valid only in context, so the UAT auth check knows it's looking for `kanidm_uat_<CREDENTIAL>`. A simple string match is more efficient in this case.

## Other implementations

[AWS token IDs have follow designated patterns](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html), say `AKIA` for IAM key, or `ASIA` for a short-term token.

Sadly we can't join [GitHub's secret scanning program](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-partner-program) because we don't run a single platform. It would be great if they could support token introspection and issuer communication.

## Further Reading

- <https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets>
