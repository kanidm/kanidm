
RADIUS Integration
------------------

RADIUS (and in the future, diameter?) is the supporting technology that enables per-user authentication
to network infrastructure. This may be through VPNs, switchports or wireless mediums. As a result
supporting RADIUS and being able to work well with it will help to make kanidm able to be used in
a broad range of applications.

Deployment Characteristics
--------------------------

In the majority of deployments, due to the centralisation of authentication, RADIUS tends to have
a one-to-one relationship with IDM systems. IE you will only have a single RADIUS infrastructure
to server your users, rather than multiple RADIUS silos backed to one IDM infrastructure.

This means that Kanidm only has to consider that a single RADIUS infrastructure will exist. We
could consider this to be a single server, or many servers that are identical, but they will all
serve the same network authentication role, arbitrating access to a single network space (even
over large geographic areas).

Generally within the network, access to different resources (IE staff vs student at a university)
comes from attributes on each account and RADIUS will interpret or proxy these to the network
devices. This could be IP ranges or vlan ids that are associated to the accounts, or even
group associations.

Due to the lack of configuration on windows and ios/macos, there is only a single universally supported
authentication type on radius, which is MSCHAPv2. This requires NTLM hash (md4) or plaintext password
storage. It's hard to overstate this - MSCHAPv2 is the only auth type that works on all devices,
out of box, with no messing around. It has to be offered.

This means whatever we do is limited now by it's requirements. For example, you can't have multiple
passwords per account (ie per-device radius pw) because of how the MSCHAPv2 chal-resp works. This
means 1 to 1 of pw to account for RADIUS.

Note that most other radius methods are not much better wrt to password storage security. In terms
of a positive user experience, having MSCHAPv2 is essential.

Nice To Have
------------

To limit the scope of damage in an attack, RADIUS passwords should be seperate from the main
account password due to their weak storage. Because these are seperate and shared between devices
this does lead to some interesting behaviours we can use.

Storing the RADIUS password in plaintext now becomes an option, meaning that we can have autoconfiguration
profile generation for clients. IE we can autogenerate ios wireless configuration profiles including
the SSID and certificate.

It also means that when a user changes their password, they don't need to change their wifi passwords.

Compromise of a radius credential will not compromise the main account, and should not even allow
login at all (except to network which is not the only security boundary).


Kanidm RADIUS Specifics
-----------------------

With the above in mind, this leads to the following conclusions:

* There is only a single RADIUS configuration profile per-kanidm topology
* A user only requires a single RADIUS infrastructure password as the network is considered a single entity and resources are arbitrated elsewhere.
* Groups define what vlan a users belongs to (and possibly other ip resources).
* The users RADIUS password is seperate from their main account, and has no other function than RADIUS authentication.
* The users RADIUS password can be server-side generated, and have pathways to distribute it to devices that remove the need for human interaction

Design Details
--------------

A single site-wide RADIUS configuration should exist, and be a system protected object with allowances for modification

The site-wide RADIUS configuration should store the ca cert of the RADIUS infra and the SSID of the site for profile generation

An extension to groups that defines a vlan *and* a priority should be added. The priority is so that
when an account is member of multiple groups that have vlan's we can arrange them by preference
falling back on the vlanid itself if needed.

A RADIUS Credential type which is a plaintext utf8 string may be present on a user.

The account may self-read the radius credential, and may ask it to regenerate, but they can not
manually define a value

Radius servers can read the radius credential to allow mschapv2 auth.

Account/AccountHP admins can not read the credential.

A default group for "radius_access" should exist, where members are able to use radius (IE we want
to avoid default all accounts can radius auth).

The radius client will be rlm_python. It will search for accounts based on name + memberof radius_access, and this will use the
radius token in rest to generate a radius data package inc the vlanid, plain pw, groups for the radius server to use.

How to make the PW easy to copy or write out for clients that don't have deployment profiles? (android apparently doesn't have these
but if they support them, someone please tell me. Similar for windows)

RADIUS wouldn't allow auth if the radius cred is locked OR the account global lock is in place.


One of my key notes here is to keep the RADIUS configuration simple but broadly applicable, while
also using existing mechanics (memberof + filtering) to determine vlans etc.

Notes on Trusts
---------------

There are two possibilities here:

* One account - one radius pw - two sites

We replicate the radius credential to the trusted domain, so the user has the same radius password
in both locations. A question is how the user would auto-add their profile to their devices here
on the remote site, because they would need to be able to access the configuration. This would
necesitate the user logging into the "trust" site to get the configuration profile anyway.

* One account - two sites - two passwords

We do not replicate the radius credential to the trusted domain, and we expect the user to login
to the trust site, generate a radius credential and deploy any site specific configuration via
that login. This would limit damage if a domain was compromised.

Given that the user would have to login to the trusted side to get the network configuration details
anyway, at this step the radius credential could be created. However, this raises a question of
how valuable that "trust" is beyond simply being a credential and administration silo.

I honestly think this is the better idea, it makes more sense because we trust the user to login
and then generate per-site details. It also means even in the trust, we aren't distributing credentials
and the point of a trust IS the credential siloing.


Future
------

If it was possible that we could have deployment profiles for android, ios/macos and windows, then
we could switch to full CA generation and automation for auth instead of pw. This would make the
auth stronger, and certainly would fix the per-device credential issue. Care needs to be taken in
how we revoke certs of course to be sure this process is robust.

