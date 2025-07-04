# Identifiable Secrets

Kanidm tokens should have a unique pattern, making them easy to recognize. This is crucial for security systems that aim
to prevent incorrect credential storage. Without a distinct pattern, like with bare JWTs that look like any
base64-encoded data, we risk false alarms.

## The Kanidm pattern

```text
kanidm_<CREDENTIAL>
```

Where:

- `<CREDENTIAL>` is the actual credential.

We can make this compatible with current validators by checking if the submitted token starts with `kanidm_`. If it
does, we remove that part and continue with validation.

Regular expressions should NOT be used. Credentials are valid only in context, so the auth check knows it's looking for
`kanidm_<CREDENTIAL>`. A simple string match and split is more efficient in this case.

## Other implementations

[AWS token IDs have follow designated patterns](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html),
say `AKIA` for IAM key, or `ASIA` for a short-term token.

Sadly we can't join
[GitHub's secret scanning program](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-partner-program)
because we don't run a single platform. It would be great if they could support token introspection and issuer
communication.

## Further Reading

- <https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets>
