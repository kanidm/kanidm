# Choosing a Domain Name

Through out this book, Kanidm will make reference to a "domain name". This is your chosen DNS domain
name that you intend to use for Kanidm. Choosing this domain name however is not simple as there are
a number of considerations you need to be careful of.

{{#template templates/kani-warning.md imagepath=images/ title=Take note! text=Incorrect choice of
the domain name may have security impacts on your Kanidm instance, not limited to credential
phishing, theft, session leaks and more. It is critical you follow the advice in this chapter. }}

## Considerations

### Domain Ownership

It is recommended you use a domain name within a domain that you own. While many examples list
`example.com` throughout this book, it is not recommended to use this outside of testing. Another
example of risky domain to use is `local`. While it seems appealing to use these, because you do not
have unique ownership of these domains, if you move your machine to a foreign network, it is
possible you may leak credentials or other cookies to these domains. TLS in a majority of cases can
and will protect you from such leaks however, but it should not always be relied upon as a sole line
of defence.

Failure to use a unique domain you own, may allow DNS hijacking or other credential leaks in some
circumstances.

### Subdomains

Due to how web browsers and webauthn work, any matching domain name or subdomain of an effective
domain may have access to cookies within a browser session. An example is that `host.a.example.com`
has access to cookies from `a.example.com` and `example.com`.

For this reason your kanidm host (or hosts) should be on a unique subdomain, with no other services
registered under that subdomain. For example, consider `idm.example.com` as a subdomain for
exclusive use of kanidm. This is _inverse_ to Active Directory which often has it's domain name
selected to be the parent (toplevel) domain (`example.com`).

Failure to use a unique subdomain may allow cookies to leak to other entities within your domain,
and may allow webauthn to be used on entities you did not intend for which may or may not lead to
some phishing scenarioes.

## Examples

### Good Domain Names

Consider we own `kanidm.com`. If we were to run geographical instances, and have testing
environments the following domain and hostnames could be used.

_production_

- origin: `https://idm.kanidm.com`
- domain name: `idm.kanidm.com`
- host names: `australia.idm.kanidm.com`, `newzealand.idm.kanidm.com`

This allows us to have named geographical instances such as `https://australia.idm.kanidm.com` which
still works with webauthn and cookies which are transferable between instances.

It is critical no other hosts are registered under this domain name.

_testing_

- origin: `https://idm.dev.kanidm.com`
- domain name: `idm.dev.kanidm.com`
- host names: `australia.idm.dev.kanidm.com`, `newzealand.idm.dev.kanidm.com`

Note that due to the name being `idm.dev.kanidm.com` vs `idm.kanidm.com`, the testing instance is
not a subdomain of production, meaning the cookies and webauthn tokens can NOT be transferred
between them. This provides proper isolation between the instances.

### Bad Domain Names

`idm.local` - This is a bad example as `.local` is an mDNS domain name suffix which means that
client machines if they visit another network _may_ try to contact `idm.local` believing they are on
their usual network. If TLS verification were disabled, this would allow leaking of credentials.

`kanidm.com` - This is bad because the use of the top level domain means that any subdomain can
access the cookies issued by `kanidm.com`, effectively leaking them to all other hosts.

Second instance overlap:

_production_

- origin: `https://idm.kanidm.com`
- domain name: `idm.kanidm.com`

_testing_

- origin: `https://dev.idm.kanidm.com`
- domain name: `dev.idm.kanidm.com`

While the production instance has a valid and well defined subdomain that doesn't conflict, because
the dev instance is a subdomain of production, it allows production cookies to leak to dev. Dev
instances may have weaker security controls in some cases which can then allow compromise of the
production instance.
