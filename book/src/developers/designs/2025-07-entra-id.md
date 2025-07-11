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
to function as a client to Kanidm, then we will be able to extend this to allow Windows to authenticate to Kanidm. This
demonstrates that an opensource Entra ID alternative is viable.

With a viable opensource replacement available, this may allow regulatory pressure to be exerted on Microsoft to allow
open Windows to use third party Entra ID compatible services.

This is important as today Windows is coded to only support Microsofts EntraID services. This limits Windows
authentication options for users to EntraID or on prem ADDC.

However, due to the lack of TLS CA pinning in Windows this means that an initial proof of concept could be made by MITM
techniques to redirect clients to our implementation.

> NOTE: Microsoft's released Linux Intune clients do perform TLS CA pinning however.

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
Microsoft. This improves the security of authentication for all users of both Entra ID and our reimplementation. The
himmelblau project has already discovered and disclosed a number of these issues.

### Ability to Improve the End Result

Kanidm as a project has high standards for quality, and this will be a positive influence on the potential success and
security of the project as we can influence the direction in a way that prioritises quality.

## Cons / Risks (To Kanidm)

### Does not address the underlying issues

To me, this is the most important risk present.

The underlying issue is that making
[3rd party authentication modules](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture)
in Windows is "strongly discouraged" and mostly undocumented. While this proposal would allow Windows to authenticate to
3rd parties, it doesn't resolve the need to be able to create new authentication modules for Windows client machines.

What we want is Windows to authenticate to Kanidm on our terms - we want to create our own Windows authentication module
based on our own design, rather than having to follow what Microsoft has done for Entra ID. This proposal achieves
Windows client authentication in a way that leaves control of the specification with Microsoft, there is no guarantee
that Windows will even gain third party Entra ID server support, and Microsoft could update the specification without
notice breaking our integrations.

### Elevated risk of Security Issues

Since we did not design the Entra ID protocols, they may have security issues we are not aware of. Additionally these
protocols are complex and the
[documentation is incomplete](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/2f7d8875-0383-4058-956d-2fb216b44706)
where it does exist. This may lead us to make a mistake in our reimplementation that leads to security issues.

Importantly within this is that to remain compatible with Windows, we would need to do the what Windows expects, so we
have no room to adjust for improve the protocol - only limit what we may offer to the client. If the core protocol that
is required for Windows authentication is structurally vulnerable, then we have few choices available to us.

### Not in control of specification

A valuable part of Kanidm's success has been "nearly complete control" over all specifications we implement, meaning we
can implement them in a minimal and secure manner. By having to implement someone else's specification, we must follow
what Microsoft do to the letter. This could lead to security issues (as above), but also Microsoft can change the
specification and server side behaviour at anytime in a way that can break authentication. We would be playing "forever
catch up", with potentially no specification, and no input to the development of Entra ID and our needs.

A suggestion is that we can extend the protocols with more secure techniques for our own use cases in future, but we
would still need to support the "minimum" viable that Windows does to maintain interop.

### User Experience

As we are not in control of the specification, the user experience is limited to what Microsoft implements. This may
limit us and what we can do for users. In some cases certain experiences would be impossible, such as the use of the
Microsoft Authenticator app since that is completely controlled by Microsoft. This limits what we could offer to Windows
users/clients.

## Cons / Risks (To the Project as a Whole)

### Regulatory pressure may not eventuate.

There is a not-insignificant risk that the regulatory pressure may not eventuate, meaning that Windows will not be made
able to authenticate to 3rd party EntraID services. This would leave us with an interface that we would either need to
maintain for future hope of that pressure to exist. In previous cases, regulatory pressure has taken years to manifest
meaning that this is a project for "the long haul".

Additionally, there are ways to deflect pressure, such as Microsoft pointing at ADDC and saying "well you can already,
self host so we don't need another open spec here".

> IMPORTANT: Microsoft _may_ tie EntraID login to
> [licensing of Windows editions](https://www.microsoft.com/en-au/microsoft-365/enterprise/microsoft365-plans-and-pricing).
> We do not want to participate in activity that would allow license violations of Windows, so we need to be careful in
> this area. This may require changes to Windows in someway.

#### Windows Licensing

This may lead to users who want to use their Windows 11 CALs or Licenses via Entra. We probably don't want to go near
this for obvious legal reasons. However users may expect this capability since it is what Entra provides today.

### Lack of Corporate Interest

While it's possible that we could create an Entra ID compatible server, this may not mean that consumers want to use it.
This is a similar situation that Samba 4 ADDC has fallen into. Many companies would rather stick with the Microsoft
ecosystem for their clients and servers, and would not want to mix and match Windows clients with opensource servers.
This has led to little to no interest (or money) from clients.

If this combines with no ongoing support or maintenance, we would be left supporting a large feature without the
resources to back or secure it.

## Possible Paths Forward

### Do Not Accept the Proposal

This presents the least risk to Kanidm. However, it would mean that sernet may follow other avenues, and if they are
successful, leaves Kanidm without Windows client support. For example, this could result in a Kanidm fork or a new IDM
based on other projects.

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

### Make an SSP

Make our own SSP, even though it's "black box". Microsoft are not in support of this and this option poses many
challenges but it means that any other IDP could then use our SSP framework to integration authentication with Windows.

### Design a Machine Protocol

Rather that implement an SSP, we design a generic opensource Authentication protocol and specification. This way we can
become an open server implementation of that protocol, and we can request microsoft to make an SSP that implements this.

This way Microsoft still controls the SSP, but we have a protocol/specification that improves upon (and is not limited
by) what Entra ID does. This however may be a steeper uphill battle, as Microsoft has little reason to implement this,
and it will be harder to generate regulatory pressure.
