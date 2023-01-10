LDAP Gateway
------------

LDAP is a legacy protocol for accessing directory (user, group, other) data over a network. Despite
it's complex nature, it has been the staple of authentication and authorisation for many years, where
many enterprise or unix focused applications are guaranteed to integrate with LDAP (even contrast to
newer systems like SAML/OAuth).

We can not expect every application to update to use the Kanidm specific API's nor any other modern
API we offer, so we should allow these applications to at least be able to read into Kanidm via
an LDAP interface.

A major use case is legacy systems that Kanidm's native unix services aren't available on, so these
would be better served via LDAP - of course, the native kanidm unix integrations are better
than existing LDAP integration choices, so we prefer those over any other pam/nss provider.

Limitations
===========

LDAP is a complex protocol, with many esoteric options that the majority of clients do not support
or require. To become fully rfc4511 compliant, would be a large amount of time for very little
gain.

The majority of value is in a working search and bind operation set. The LDAP gateway to Kanidm
will be Read Only as a result. The ability to write via LDAP will not be supported.

Most LDAP servers offer their schema in a readonly interface. Translating Kanidm's schema into a way
that clients could interpret is of little value as many clients do not request this, or parse it.

While Kanidm is entry based, and NoSQL, similar to LDAP, our datamodel is subtely different enough
that not all attributes can be representing in LDAP. Some data transformation will need to occur as
a result to expose data that LDAP clients expect. Not all data may be able to be presented, nor
should it (ie radius_secret, you should use the kanidm radius integration instead of the LDAP
interface, as the kanidm interface is more efficient).

Security Considerations
=======================

LDAP has a number of security considerations associated, but we already have to address these
in kanidm. These are:

* Limits on query result sizes.
* Limits on filter recursion or size.
* Limits of number of threads that can be processing operations for a user.
* Rate limiting of authentication attempts.
* Access controls related to entries.

Due to this, LDAP as an interface does not yield greater risk as all of these concerns are already
required to be addressed in the main Kanidm server core. Due to the architecture in Kanidm, all
improvements to security in the core will impact LDAP as well.

Design
======

An Actix TCP Stream gateway will be added that is able to translate LDAP operations into events for
the server core. These events will be limited to Bind and Search.

Search Base
===========

This is derived from the domain name. All entries are presented in a flat scope, the same as Kanidm
to avoid trying to "create" a fake hierarchy.

Access Controls
===============

LDAP only supports password based authentication for the majority of clients. As LDAP is a "posix like"
interface, and could be used for posix authentication, LDAP binds will use the posix account password.
As the posix password is *not* equivalent in privilege to the main account credentials, accounts
should NOT gain their access controls of the primary credential. All accounts, regardless of bind
state will be limited to the permissions of "Anonymous".

Anonymous binds may be disabled to LDAP (via locking the Anonymous account), but bind accounts will
still function using Anonymous equivalent read permissions.

Filter Transformations
======================

Some common LDAP filters for applications may be hardcoded or unable to change to other attributes.
This means we need to be able to map some common requests. These do not require any other changes
beyond the attribute name:

| Kanidm Attribute  | LDAP Attribute    |
| ----------------- | ----------------- |
| name              | cn                |
| spn               | uid               |
| gidnumber         | uidnumber         |
| class             | objectClass       |

We will accept (and prefer) that Kanidm attribute names are provided in the LDAP filter for applications
that can be customised.

Compatibility Attributes
========================

Some attributes exist in LDAP that have no direct equivalent in Kanidm. These are often from existing
LDAP deployments and may need to be carried through else certain associations are broken. The major
two are:

* nsUniqueId
* EntryUUID

These should be provided through an ldapCompat class in kanidm, and require no other transformation. They
may require generation from the server, as legacy applications expect their existence and kanidm created
accounts would need the attributes to exist to work with these.

Entry and Attribute Transformations
===================================

Some attributes and items will need transformatio to "make sense" to clients. This includes:

member/memberOf: Member in LDAP is a DN, where in Kanidm it's a reference type with SPN. We will need
to transform this in filters *and* in entries that are sent back.

gecos: This needs synthesisation from displayname

homeDirectory: This needs to match the rules in kanidm_unix_int, especially once trusts are added (likely to be uuid based).

Kanidm is closest to rfc2307bis due to the structure of it's memberOf attributes and other
elements, so this is what we will "look like" but may not strictly conform to.


Kanidm Required Changes (TODO list)
===================================

* The TCP gateway with options to enable/disable from CLI options
*   domain name -> basedn at startup
* RootDSE generator for the LDAP subsystem to indicate options/basedn/etc
* LDAPBindEvent
* Schema Additions -> LDAPCompatId
* LDAPCompatId Plugin Generator
* EntryReduced -> LDAPEntry
*    Attribute Generation/Transformation in LDAPEntry
* LDAPWhoamiEvent (Anonymous Event source)
* LDAPFilter -> Filter
* LDAPSearchEvent (Anonymous Event source)



