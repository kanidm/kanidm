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

## High Level Suggestions

There are the ideas today that I have - there may be others!

* Service Accounts can have attached roles.
* Keep concerns separate.
* Bit of A, bit of B, cleanup.

## Current state of affairs

We have:

* Break glass accounts are service accounts, may not have delegated management.
* OAuth2 is not a service account, supports delegated management.
* Service accounts can be group or user managed.
* Applications (To Be Introduced) is an extension of a Service account.

From this we can see that we have some separation, but also some cross over of functionality.
break glass isn't delegated, but service account is, OAuth2 isn't an SA, but Applications are.

## Attach roles to service accounts.

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

## Separate Concerns

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

## Bit of A, bit of B, cleanup

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






