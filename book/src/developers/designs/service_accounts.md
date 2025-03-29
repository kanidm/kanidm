# Service Account Improvements - 2025

Initially when service accounts were added to Kanidm they were simply meant to be "detached"
accounts that could be used for some API access to Kani, or some other background tasks.

But as the server has evolved we need to consider how we can use these in other ways.

We have extented the OAuth2 client types to now almost act like a service account, especially
with the behaviour of things like a client credentials grant.

At this point we need to decide how to proceed with service accounts and what shape they could
take in the future.

## Prior Art

* (Microsoft AD-DS Service Accounts)[https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts]
* (FreeIPA Service Principals)[https://www.freeipa.org/page/Administrators_Guide#managing-service-principals]

Note that both of these have some kerberos centric ideas as KRB requires service accounts to mutually
authenticate to clients, which means they need to maintain credentials. This is different to our needs,
but there are still some ideas in these docs worth knowing about and considering like group managed
service accounts (gMSA).

## Current state of affairs

We have:

* Break glass accounts are service accounts, may not have delegated management.
* OAuth2 is not a service account, supports delegated management.
* Service accounts can be group or user managed.
* Applications (To Be Introduced) is an extension of a Service account.

From this we can see that we have some separation, but also some cross over of functionality.
break glass isn't delegated, but service account is, OAuth2 isn't an SA, but Applications are.

## Capabilities

In order to properly handle this, we don't want to grant unbounded abilities to types, we don't
want to fully merge them, but we want to be able to mix-match what they require.

This also makes it possible in the future that we can more easily assign (or remove) a capability
from an account type.

To achieve this we should introduce the idea of capabilities - capabilities can act via schema
classes, and we can extend the schema such that only the parent class needs to know that the
capabilities class is required.

This allows us to nominate more carefully what each role type can or can't do, and keeps things

| Capabilities    | Api Token        | OAuth2 Sessions              | Interactive Login   |
|-----------------|------------------|------------------------------|---------------------|
| OAuth2          | No               | Via Client Credentials Grant | No                  |
| Application     | Yes (ro)         | No                           | No                  |
| Service Account | Yes (rw capable) | Yes (via session grant (TBD) | Yes (to be removed) |
| Machine Account | Yes (ro)         | No                           | No                  |
| Break Glass     | No               | No                           | Yes                 |
| Person          | No               | Yes                          | Yes                 |

A key requirement of this is that we want each role to have a defined intent - it shouldn't be
the everything role, it still needs to be focused and administered in it's own right.

|                 | Intent                                                                                                                                                                                    |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OAuth2          | An OAuth2 client (external server/service) that is treating Kani as the IDP it trusts to validate user authorisation to it's resources.                                                   |
| Application     | An LDAP application password context, allowing per-user/per-device/per-application passwords to validated, as well as defining group based authorisation of whom may use this application |
| Service Account | An account that belongs to a process or automation that needs to read from or write to Kanidm, or a Kanidm related service.                                                               |
| Machine Account | A domain joined machine that is reads user posix or login information. May be used to configure machine service accounts in future.                                                       |
| Break Glass     | An emergency access account used in disaster recovery.                                                                                                                                    |
| Person          | A humans owned account that needs to authenticate day to day, and self manage their own credentials. A person may need to manage other accounts and resource types                        |

This has the benefit that it makes it easier to assign the permissions via ACP (since we can filter
on the Target class *and* capability type).

### Example

An Email service has an SMTP gateway and OAuth2 web ui.

Although this is "the email service" it is made up of multiple parts that each have their own intents.

The Webui has an Oauth2 client created to define the relationship of who may access the webui.

An LDAP application is made to allow IMAP/SMTP processes to authenticate users with application passwords and
to read users PII via LDAP.

## Below was the drafting process of some ideas

### Attach roles to service accounts.

In this approach we centre the service account, and allow optional extension of other concerns. This
would make OAuth2 applications an extension of a service account. Similar Application as well.

This would mean that we create a service account first, then need a way to extend it with the
application or oauth2 types.

PROS:

* OAuth2 applications get the ability to have api tokens to kani for other functionality
* Fullstacks like a mail server get a single SA that does everything
* These whole stack service accounts get access to every auth type and feature available

CONS:

* Makes the API around service accounts a bit messier
* Compromise of the SA or SA Manager may lead to higher impact due to more features in one place
* May be confusing to administrators
* More "inheritance" of schema classes, when we may want to try to simplify to single classes in line with SCIM.
* Harder to audit capabilities
* The administration UI becomes a shitshow as the Service Account is now a kitchen sink.

### Separate Concerns

In this approach we split our concerns. This is similar to today, but taken a bit further.

In this example, we would split Application to *just* be about the concern of an authentication
domain for LDAP applications. OAuth2 stays as *just* a configuration of the client and it's behaviour.

We would change the break glass accounts to be a separate type to Service Account. Service Account
becomes closer to the concept of a pure api access account. The break glass accounts become a
dedicated "emergency access account" type.

PROS:

* Similar to today, only small cleanup needed
* Separation of concerns and credentials limit's blast radius of a possible compromise.
* Easier auditing of capabilities of each account

CONS:

* More administrative overhead to manage the multiple accounts
* Stacked applications will need mulitple configurations for a role - OAuth2, LDAP application, Service accounts for example in an email server with a WebUI.

### Bit of A, bit of B, cleanup

AKA Capabilities

Rather than fully merge all the types, or fully split them, have a *little* merge of some bits, allowing
some limited extension of actions to specific actors. Effectively we end up granting *capabilities*
to different roles, and we can add extra capabilities later if we want.

OAuth2 and Applications would gain the ability to have API tokens associated for some tasks and
could act on Kanidm, but they wouldn't be fully fleshed service accounts.

| Capabilities    | Api Token        | OAuth2 Sessions              | Interactive Login   |
|-----------------|------------------|------------------------------|---------------------|
| OAuth2          | No               | Via Client Credentials Grant | No                  |
| Application     | Yes              | No                           | No                  |
| Service Account | Yes (rw capable) | Yes (via session grant (TBD) | Yes (to be removed) |
| Break Glass     | No               | No                           | Yes                 |

PROS:

* Minimises changes to existing deployments
* Grants some new abilities within limits to other roles
* While not as locked down as separate concern proposal, still minimises the risk of compromise of an SA

CONS:

* Requires admins to have multiple accounts in some contexts (as above).
* Auditing requires knowledge of what each roles capabilities are, and what the capabilities do


