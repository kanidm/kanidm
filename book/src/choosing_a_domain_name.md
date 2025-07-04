# Choosing a Domain Name

This book makes many references to a "domain name". This is the DNS domain name that you intend to use for Kanidm.

This isn't always simple, and this chapter covers the key issues to consider when choosing a domain.

> [!WARNING]
>
> **Bad choices** of domain name may have security impacts on your Kanidm instance, not limited to credential phishing,
> theft, session leaks and more.
>
> [**Changing** domain name is hard to do](./domain_rename.md) – it not only means reconfiguring all LDAP and OAuth
> clients, but will also break all registered WebAuthn credentials for all users (which are bound to an `Origin`).
>
> It's critical that you consider and follow the advice in this chapter, and aim to get it right the first time.
>
> You'll save yourself (and your users) a lot of work later!

<!-- -->

> [!TIP]
>
> We believe these practices are applicable _regardless_ of your organisation's size (even if your Kanidm instance is
> just for you!), or if you think your organisation is not "important enough" to be the target of attacks.
>
> While some suggestions may seem "extreme" or "paranoid", they generally come from Kanidm's authors' collective decades
> of experience managing, maintaining, and securing networks and systems at both very large and very small organisations
> both inside and outside the technology industry.

## Recommendations

If you have [strict security controls for all apps on your top-level domain](#subdomains-and-cross-origin-policy), you
could run Kanidm on a subdomain of your main domain. If you owned `example.com` then you would use:

- Origin: `https://idm.example.com`
- Domain name: `idm.example.com`

You must ensure no other services beside Kanidm use `idm.example.com` or subdomains of `idm.example.com`.
`idm.example.com` would have DNS records that point to a load balancer, anycast IP or any other HA mechanism you may
choose.

> [!NOTE]
>
> Using a subdomain is the **inverse** of the common Active Directory practice of using the organisation's primary
> top-level domain directly, eg: `example.com`, where hosts would then register as `hostname.example.com`.

Running Kanidm on a _separate_ top-level domain makes it much easier to restrict changes that _could_ affect your IDM
infrastructure. For **maximum** security, your Kanidm domain name should be a subdomain of a top-level domain (or domain
under a [public suffix][ps]) that has no other services assigned it. In this example you own `example-auth.example`
which you would operate in parallel to `example.com`. No other services should use this domain or subdomains:

- Origin: `https://idm.example-auth.example`
- Domain name: `idm.example-auth.example`

### Multi-environment and regional deployments

If we were to run regional instances, and have a separate testing environment, the following domain and hostnames could
be used:

#### Production environment

- Origin: `https://idm.example.com`
- Domain name: `idm.example.com`
- Host names: `australia.idm.example.com`, `newzealand.idm.example.com`

This allows us to have named regional instances such as `https://australia.idm.example.com` which still works with
WebAuthn and cookies which are transferable between instances.

It is critical no other hosts are registered under `idm.example.com`.

#### Testing environment

- Origin: `https://idm-test.example.com`
- Domain name: `idm-test.example.com`
- Host names: `australia.idm-test.example.com`, `newzealand.idm-test.example.com`

This puts the testing instance under a separate subdomain of the top-level domain to production (`idm.example.com`), so
cookies and WebAuthn tokens can **not** be transferred between them. This provides proper isolation between the
instances.

## Bad domain names

Domains you should avoid:

<dl>

<dt>

`idm.local`

</dt>

<dd>

The `.local` top-level domain is [reserved for multicast DNS][dot-local].

If a client visits another network, it _may_ try to contact `idm.local` believing it is on its usual network. If TLS
certificate verification were disabled (or not configured correctly), this would leak credentials.

</dd>

<dt>

`example.com`

</dt>

<dd>

Using the top-level domain directly allows any subdomain of that domain to access credentials and cookies intended for
Kanidm.

</dd>

<dt>

`idm.example.nsw.gov.au`

</dt>

<dd>

[`nsw.gov.au` has opted out of being a public suffix][nsw-optout], so all domains under that suffix (except
`schools.nsw.gov.au`) share origin and cookies.

</dd>

<dt>

`idm.examplekanidm.example`

</dt>

<dd>

Kanidm is the brand for this project.

</dd>

</dl>

### Multi-instance with overlap

- Production:
  - Origin: `https://idm.example.com`
  - Domain name: `idm.example.com`

- Testing:
  - Origin: `https://test.idm.example.com`
  - Domain name: `test.idm.example.com`

While the production instance has a valid and well defined subdomain that doesn't conflict, because the testing instance
is a subdomain of production, it allows production cookies to leak to the testing environment.

Testing environments may have weaker security controls in some cases which can then allow compromise of services using
the production instance.

## Detailed Considerations

### Use a domain under your exclusive control

You should always use a domain name that you've registered and directly control its DNS.

While `example.com` and top-level domains ending in `.example` appear throughout this book,
[these are examples only][rfc2606]. You should **not** use this outside of testing.

[rfc2606]: https://datatracker.ietf.org/doc/html/rfc2606

You'll need a registered domain for a CA (certificate authority) to issue you a TLS certificate which is widely accepted
by browsers. This will also **prevent** those same CAs from issuing a certificate for that domain to _someone else_.

If you use a domain controlled by someone else (eg: a Dynamic DNS provider, or your cloud provider), they could take
over that domain _whenever they like_. They could also use control of DNS or email to convince a CA to issue a
certificate for that domain.

_Any party who holds a valid certificate for the domain can steal or issue credentials._

### Avoid non-public and reserved domains

Avoid using "made-up" (eg: `.lan`) or reserved domains (eg: [`.local`][dot-local]), because your clients may leak
credentials if they move to another network, aren't connected to a VPN, or if it
[collides with new TLDs][name-collision].

Properly-configured TLS can prevent _most_ (but not all) leakage, but defence in depth is best.

This will also ensure your infrastructure is accessible regardless of your users' local network conditions.

[dot-local]: https://www.rfc-editor.org/rfc/rfc6762.html#section-3
[name-collision]: https://en.wikipedia.org/wiki/Top-level_domain#Reserved_domains

### Domain authorities

Domain authorities can set their own eligibility policies for registering a top-level domain. They may also allow a
third-party to challenge your claim to a top-level domain, subject to a dispute resolution policy. These policies may
change over time for commercial or political reasons.

If your domain is on a ccTLD (country TLD), it may be de-registered should that country cease to exist (eg:
[as for `.io`][dot-io]).

[dot-io]: https://www.theverge.com/2024/10/8/24265441/uk-treaty-end-io-domain-chagos-islands

### Top-level domains containing "kanidm"

We ask that you **do not** use the word `kanidm` as part of your instance's _top-level_ (or [public-suffix-level][ps])
domain, eg: `contoso-kanidm.example`.

Use something like `auth`, `idm`, `login` or `sso` instead – they're shorter, too!

We're OK with you using `kanidm` in a _subdomain_ to point to your Kanidm instance, eg: `kanidm.example.com`.

We've worked hard to build this project, and using its name in conjunction with an organisation _not_ associated with
the project dilutes the name's brand value.

### Subdomains and Cross-Origin policy

Browsers allow a server on a subdomain to use intra-domain resources, and access and set credentials and cookies from
all of its parents until a [public suffix][ps]. This can allow a malicious or compromised service to attack other
services which share a parent domain.

[ps]: https://publicsuffix.org/

Public suffix rules are _mostly_ predictable, but has some exceptional cases. For example:

- `host.a.example.com` can access and set cookies for:

  - `host.a.example.com` (itself)
  - `a.example.com`
  - `example.com`

  But **not** the public suffix `.com`.

- `host.a.example.qld.gov.au` can access and set cookies for:

  - `host.a.example.qld.gov.au` (itself)
  - `a.example.qld.gov.au`
  - `example.qld.gov.au`

  But **not** any public suffix:

  - `qld.gov.au` (Queensland state government)
  - `gov.au` (Australian federal government)
  - `.au` (Australia)

- `host.a.example.nsw.gov.au` can access and set cookies for:

  - `host.a.example.nsw.gov.au` (itself)
  - `a.example.nsw.gov.au`
  - `example.nsw.gov.au`
  - `nsw.gov.au` ([NSW state government has opted out][nsw-optout])

  But **not** any public suffix:

  - `gov.au` (Australian federal government)
  - `.au` (Australia)

[nsw-optout]: https://bugzilla.mozilla.org/show_bug.cgi?id=547985

This can be an issue if Kanidm shares a domain with:

- applications which serve raw, user-supplied data in APIs (eg: blob/file storage and [Matrix homeservers][matrix-csp])
- third-party servers _outside_ of your organisation's control (eg: SaaS apps)
- anything which can be deployed to with minimal oversight (eg: a web host that allows uploading content via unencrypted
  FTP)
- DNS entries that resolve to arbitrary IP addresses (eg: `192-0-2-1.ipv4.example.com` to `192.0.2.1`, and `192.0.2.1`
  is not under the authority of `example.com`)

[matrix-csp]: https://github.com/element-hq/synapse/blob/develop/README.rst#security-note

In most cases, hosting Kanidm on a subdomain of a separate top-level (or _existing_ [public-suffix level][ps]) domain
(eg: `idm.contoso-auth.example`) is sufficient to isolate your Kanidm deployment's `Origin` from other applications and
services.

> [!WARNING]
>
> There is generally **no need** to request additions to [the public suffix list][ps] to deploy Kanidm securely, _even
> for multi-environment deployments_.
>
> The **only** exception is to _remove_ an _existing_ opt-out that affects your domain where it must operate under a
> particular suffix (eg: a NSW government agency using `example.nsw.gov.au`).
>
> Such requests are a [major burden for the _volunteer-operated_ list][ps-diffusion], can take
> [months to roll out to clients][ps-rollout], and changes may have unintended side-effects.
>
> By comparison, registering a separate domain is easy, and takes minutes.

[ps-diffusion]: https://github.com/publicsuffix/list/wiki/Third-Party-Diffusion
[ps-rollout]: https://github.com/publicsuffix/list/wiki/Guidelines#appropriate-expectations-on-derivative-propagation-use-or-inclusion

> [!TIP]
>
> Web apps (and APIs) that authenticate with [OAuth 2.0/OpenID Connect](./integrations/oauth2.md) **never** need to
> share cookies or Origin with Kanidm, so they **do not** need to be on the same top-level (or
> [public-suffix-level][ps]) domain.
>
> Large public auth providers (eg: Google, Meta, Microsoft) work the same way with both first and third-party web apps.

### Kanidm requires its own hostname

Kanidm must be the _only_ thing running on a hostname, served from `/`, with all its paths served as-is.

It cannot:

- be run from a subdirectory (eg: `https://example.com/kanidm/`)
- have _other_ services accessible on the hostname in subdirectories (eg: `https://idm.example.com/wiki/`)
- have _other_ services accessible over HTTP or HTTPS at the same hostname on a different port (eg:
  `https://idm.example.com:8080/`)

These introduce similar security risks to the [subdomain issues described above](#subdomains-and-cross-origin-policy).

One reasonable exception is to serve [ACME HTTP-01 challenges][acme-http] (for Let's Encrypt) at
`http://${hostname}/.well-known/acme-challenge/`. You'll need a _separate_ HTTP server to respond to these challenges,
and ensure that only authorised processes can request a certificate for Kanidm's hostname.

[acme-http]: https://letsencrypt.org/docs/challenge-types/#http-01-challenge

> [!TIP]
>
> The `/.well-known/` path ([RFC 8615][RFC 8615]) can be assigned security-sensitive meaning in other protocols, similar
> to [ACME HTTP-01][acme-http].
>
> Kanidm currently uses this path for OpenID Connect Discovery, and may use it for other integrations in the future.

[RFC 8615]: https://datatracker.ietf.org/doc/html/rfc8615

### Avoid wildcard and widely-scoped certificates

CAs can issue wildcard TLS certificates, which apply to all subdomains in the same domain (eg: `*.example.com`).

This is used by some organisations to avoid leaking information about what services exist on a domain in certificate
transparency logs. However, this information will exposed _anyway_ whenever a client makes a DNS query.

If a service is issued a wildcard TLS certificate which _also_ covers a Kanidm installation on the same domain, any DNS
hijacking could let that service impersonate Kanidm to those clients, and steal credentials.

While DNS-over-HTTPS generally prevents local hijacking, it's
[possible for a network to disable it when automatically enabled][disable-doh], or just block it entirely.

[disable-doh]: https://support.mozilla.org/en-US/kb/canary-domain-use-application-dnsnet

Sharing a single certificate between many services increases the risk that the private key may be exposed, and broadens
the impact scope.

### Separate production and testing environments

If running more than one instance of Kanidm, ensure that no two deployments share the same subdomain. This prevents
credential and cookie transfers between the two environments. For example:

- Production: `idm.example.com`
- Testing: `idm-test.example.com`

If you instead had an instance of Kanidm at `idm.example.com` for production and another at `test.idm.example.com` for
testing, then the test instance could access the credentials and cookies of the production environment.

This also prevents credentials intended for the test environment from being used in production (where there may be
stricter controls).

### Regional deployments

You could have multiple instances of Kanidm configured with replication, with a single domain name and origin (eg:
`idm.example.com`).

You could then make regional instances accessible from different host names (eg: `au.idm.example.com` and
`nz.idm.example.com`).

This allows credentials and cookies to be freely transferred between hosts that are part of a single environment.
