# Oauth2 Application Listing

A feature of some other IDM systems is to also double as a portal to linked applications. This
allows a convinent access point for users to discover and access linked applications without having
to navigate to them manually. This naturally works quite well since it means that the user is
already authenticated, and the IDM becomes the single "gateway" to accessing other applications.

## How it should look

- The user should ONLY see a list of applications they _can_ access
- The user should see a list of applications with "friendly" display names
- The list of applications _may_ have an icon/logo
- Clicking the application should take them to the location

## Access Control

The current design of the oauth2 resource servers (oauth2rs) is modeled around what the oauth2
protocol requires. This defines that in an oauth2 request, all of the requested scopes need be
granted else it can not proceed. The current design is:

- scope maps - a relation of groups to the set of scopes that they grant
- implicit scopes - a set of scopes granted to all persons

While this works well for the oauth2 authorisation design, it doesn't work well from the kanidm side
for managing _our_ knowledge of who is granted access to the application.

In order to limit who can see what applications we will need a new method to define who is allowed
access to the resource server on the kanidm side, while also preserving ouath2 semantics.

To fix this the current definition of scopes on oauth2 resource servers need to change.

- access scopes - a list of scopes (similar to implicit) that are used by the resource server for
  granting access to the resource.
- access members - a list of groups that are granted access
- supplementary scopes - definitions of scope maps that grant scopes which are not access related,
  but may provide extra details for the account using the resource

By changing to this method this removes the arbitrary implicit scope/scope map rules, and clearly
defines the set of scopes that grant access to the application, while also allow extended scopes to
be sent that can attenuate the application behaviour. This also allows the access members reference
to be used to generate knowledge on the kanidm side of "who can access this oauth2 resource". This
can be used to limit the listed applications to these oauth2 applications. In addition we can then
use these access members to create access controls to strictly limit who can see what oauth2
applications to the admins of oauth2 applications, and the users of them.

To support this, we should allow dynamic groups to be created so that the 'implicit scope' behaviour
which allow all persons to access an application can be emulated by making all persons a member of
access members.

Migration of the current scopes and implicit scopes is likely not possible with this change, so we
may have to delete these which will require admins to re-configure these permissions, but that is a
better option than allowing "too much" access.

## Display Names / Logos

Display names already exist.

Logos will require upload and storage. A binary type exists in the db that can be used for storing
blobs, or we could store something like svg. I think it's too risky to "validate" images in these
uploads, so we could just store the blob and display it?
