
== User Settings Display Web UI

We need a usable centralized location for users to view and manage their own user settings.
User settings do not envelop credentials, these have their own flow as they are also used in user setup.

 - Writing new values requires a writable session -> we will make the user reauthenticate to obtain a temporary profile-update-token when they want to update their user settings.
 - The UI must display and make editable:
   - user attributes
   - user ssh public-keys
 - The UI must display:
   - user credential status as per [credential-display.rst](credential-display.rst)
   - user groups

=== User attributes
These consist of: 
 - username
 - displayname
 - legal name
 - email address
In the future:
 - picture
 - zoneinfo/timezone
 - locale/preferred language
 - other business related attributes: address, phone number, ...

==== Displaying attributes
Attributes should be displayed with
 - their descriptive name with tooltips or links if the name may be confusing to non IT people.
 - their current value OR if not set: some clear indication that the attribute is not set.
 - A method to edit the attribute if it is editable

==== Editing attributes
Users must be able to edit attributes individually.
Users should be able to see their changes before saving them. 
  E.g. via a popup that shows the old vs new value asking to confirm.

==== TODO: Personal Identifiable Information attributes (currently we don't have these attributes)
Certain information should not be displayed in the UI without reauthentication:
 - addresses
 - phone numbers
 - personal emails
 - birthdate

=== SSH public keys
Ssh public key entries in kanidm consist of a:
 - name : practically the ID of the key in kanidm
 - value : the public key

A user may want to change their laptop ssh key by updating the value while keeping the name the same.
// TODO: Should a user be allowed to rename their kanidm ssh keys ?

==== Displaying ssh keys
Due to their long length they should be line-wrapped into a text field so the entirety is visible when shown.
To reduce visible clutter and inconsistent spacing we will put the values into collapsable elements.

These collapsed elements must include:
 - name
 - value's key type (ECDSA, rsa, ect..)
and may include:
 - value's comment, truncated to some max length


==== Editing keys
When editing keys users must be able to add keys, remove keys and update individual key values
Each action will be committed immediately, thus proper prompts and icons indicating this must be shown (like a floppy disk save icon ?)

=== Credential status
Described in [credential-display.rst](credential-display.rst)
Must inform the user of the credential update/reset page, since it is very related and might be what they were looking for instead.

=== User groups
Mostly a technical piece of info, should not be in direct view to avoid confusing users.
Could be displayed in tree form. 
