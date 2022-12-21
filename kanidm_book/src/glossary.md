# Glossary

This is a glossary of terms used through out this book. While we make every effort to explains terms
and acronyms when they are used, this may be a useful reference if something feels unknown to you.

## Domain Names

- domain - This is the domain you "own". It is the highest level entity. An example would be
  `example.com` (since you do not own `.com`).
- subdomain - A subdomain is a domain name space under the domain. A subdomains of `example.com` are
  `a.example.com` and `b.example.com`. Each subdomain can have further subdomains.
- domain name - This is any named entity within your domain or its subdomains. This is the umbrella
  term, referring to all entities in the domain. `example.com`, `a.example.com`, `host.example.com`
  are all valid domain names with the domain `example.com`.
- origin - An origin defines a URL with a protocol scheme, optional port number and domain name
  components. An example is `https://host.example.com`
- effective domain - This is the extracted domain name from an origin excluding port and scheme.

## Accounts

- trust - A trust is when two Kanidm domains have a relationship to each other where accounts can be
  used between the domains. The domains retain their administration boundaries, but allow cross
  authentication.
- replication - This is the process where two or more Kanidm servers in a domain can synchronise
  their database content.
- UAT - User Authentication Token. This is a token issue by Kanidm to an account after it has
  authenticated.
- SPN - Security Principal Name. This is a name of an account comprising it's name and domain name.
  This allows distinction between accounts with identical names over a trust boundary

## Internals

- entity, object, entry - Any item in the database. Generally these terms are interchangeable, but
  internally they are referred to as Entry.
- account - An entry that may authenticate to the server, generally allowing extended permissions
  and actions to be undertaken.

### Access Control

- privilege - An expression of what actions an account may perform if granted
- target - The entries that will be affected by a privilege
- receiver - The entries that will be able to use a privilege
- acp - an Access Control Profile which defines a set of privileges that are granted to receivers to
  affect target entries.
- role - A term used to express a group that is the receiver of an access control profile allowing
  it's members to affect the target entries.
