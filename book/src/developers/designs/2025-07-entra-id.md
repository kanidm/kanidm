# Entra ID / Azure AD compatability proposal

A proposal has been made by [SerNET](https://www.sernet.com/) that they wish to invest in the building of an Entra ID /
Azure AD compatible IDM service. This may be initially supported be EU grant funding.

David Mulder, the creator of the [himmelblau](https://github.com/himmelblau-idm/) project has proposed that Kanidm could
be the IDM service backend, where an Entra ID compatible authentication module would be added.

Himmelblau and Kanidm already have many connections and projects and collaborators. As himmelblau is already a working
client to Entra ID, and Kanidm is a full fledged IDM, this existing collaboration and relationship makes it a natural
fit that we could work together on this proposal.

In this document, we want to examine the pros, cons, and risks of this proposal.

## Goal of the Proposal

The goal would be to add compatibility for Kanidm to allow Himmelblau as an authentication client. If Himmelblau is able
to function as a client to Kanidm, this demonstrates that an opensource Entra ID replacement is viable.

With a viable opensource replacement available, this may allow regulatory pressure to be exerted on Microsoft to allow
open Windows to use third party Entra ID compatible services.

This is important as today Windows is coded to only support Microsofts EntraID services and uses TLS CA pinning to
ensure that a 3rd party can't MITM this process. This limits Windows authentication options for users to EntraID or on
prem ADDC.

## Pros

### Improved collaboration between Himmeblau and Kanidm

The Himmelblau project uses a lot of Kanidm source code. By having an Entra ID compatible server, we would be able to
merge and collabore more to "shrink the gap" between our projects. This would also give Himmelblau improved access to
client testing since they would be able to test against a provider.

### Kanidm gains client machine support

Kanidm has wanted domain-joined machine support for a long time - this would allow Kanidm to use the existing
capabilities of Himmeblau rather than inventing our own specification for this. Himmelblau also has some really cool
native desktop integrations too!

### Funding and Developers

This would bring in funding and developers to the project, allowing us to improve a number of features that would be
EntraID adjacent, especially around the WebUI components.

### Ability to authenticate Windows to Kanidm

This has been a long desired feature, and it would be excellent for Windows to be able to authenticate to Kanidm,
especially in environments that want self-hosted IDM. This is especially of interest to home labs and small business
from my understanding.

### Potential to find and disclose security risks

By implementing Entra ID as a server, we may find security vulnerabilities in the process that we can disclose to
Microsoft. This improves the security of authentication for all users of both Entra ID and our reimplementation.

## Cons / Risks

### Does not address the underlying issues

To me, this is the most important risk present.

The underlying issue is that making
[3rd party authentication modules](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture)
in Windows is "strongly discouraged" and mostly undocumented. While this proposal would allow Windows to authenticate to
3rd parties, it doesn't resolve the need to be able to create new authentication modules for Windows client machines.

What we want is Windows to authenticate to Kanidm on our terms. This proposal achieves that in a way that still leaves a
lot of control with Microsoft, and we still can't make our own Windows client authentication modules.

### Regulatory pressure may not eventuate.

There is a not-insignificant risk that the regulatory pressure may not eventuate, meaning that Windows will not be made
able to authenticate to 3rd party EntraID services. This would leave us with an interface that we would either need to
maintain for future hope of that pressure to exist, or an interface that is not as good as a clean room implementation
could have been.

### Lack of Corporate Interest

While it's possible that we could create an Entra ID compatible server, this may not mean that consumers want to use it.
This is a similar situation that Samba 4 ADDC has fallen into. Many companies would rather stick with the Microsoft
ecosystem for their clients and servers, and would not want to mix and match Windows clients with opensource servers.
This has led to little to no interest (or money) from clients.

If this combines with no ongoing support or maintenance, we would be left supporting a large feature without the
resources to back or secure it.

### Elevated risk of Security Issues

Since we did not design the Entra ID protocols, they may have security issues we are not aware of. Additionally these
protocols are complex and undocumented, and we may make a mistake in their implementation that leads to security issues.

### Not in control of specification

A valuable part of Kanidm's success has been "nearly complete control" over all specifications we implement, meaning we
can implement them in a minimal and secure manner. By having to implement someone else's specification, we must follow
what Microsoft do to the letter. This could lead to security issues (as above), but also Microsoft can change the
specification and server side behaviour at anytime. We would be playing "forever catch up", with no input to the
development of Entra ID and it's opensource needs.

### User Experience

As we are not in control of the specification, the user experience is limited to what Microsoft implements. This may
limit us and what we can do for users. In some cases certain experiences would be impossible, such as the use of the
Microsoft Authenticator app since that is completely controlled by Microsoft.

## Possible Paths Forward

### Do Not Accept the Proposal

This presents the least risk to Kanidm. However, it would mean that sernet may follow other avenues, and if they are
successful, leaves Kanidm without Windows client support.

### Create an External Project that has Swappable Backends

This would create the EntraID compatible server as a "middleware" that can be layered over other services. This is the
most portable, allowing the EntraID api's to be used by other identity projects. The issue would be that EntraID has a
number of complex requirements that could not be served by all backends such as LDAP, and projects like Kanidm that want
complete control of authentication policy may not be able to exert that via a middleware.

### Native Integration

This would be where the EntraID apis are natively integrated to Kanidm. This would still be somewhat modular, as the
Kanidm server is designed to be layered, and EntraID would not require access to the deeper parts of the server. This
gives EntraID compatability the most chance to succeed, because then we can adapt to the needs of EntraID and expose
high quality interfaces for the project. However this also brings the most maintenance burden. Worst case, EntraID
support could be removed provided we are disciplined in how the feature is added.
