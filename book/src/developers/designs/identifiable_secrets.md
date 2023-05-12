# Identifiable Secrets

It should be possible to identify a token issued by Kanidm from its pattern, so that humans and systems can tell what they're dealing with.

This is especially important with security systems that attempt to stop folks from saving credentials where they shouldn't be. Bare JWTs largely look like any other base64-encoded noise, so matching on them by default is prone to false-positives.

## The Kanidm pattern

> **RFC Discussion here**
>
> An alternative pattern could be just `kanidm_<CREDENTIAL>`, and folks can work it out themselves what they've got.

```text
kanidm_<TYPE>_<CREDENTIAL>
```

Where:

- `<TYPE>` is the cred type, eg OAuth secret, UAT etc.
  - uat
  - ors
  - unx
- `<CREDENTIAL>` is the credential.

This can be made backwards-compatible from the validation side with a pre-validation check where we check if the submitted token starts with `kanidm_\w+_`, and if so, strip it off, then carry on with the validation. 

Regular expressions should NOT be used - since they're contextual - the UAT auth check knows it's looking for `kanidm_uat_<CREDENTIAL>` so a simple string match is much more efficient.

## Other implementations

[AWS token IDs have follow designated patterns](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html), say `AKIA` for IAM key, or `ASIA` for a short-term token.

Sadly we can't join [GitHub's secret scanning program](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-partner-program) because we don't run a single platform, but maybe if they supported token introspection and contacting the issuer, that'd be neat.

## References

- <https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets>
