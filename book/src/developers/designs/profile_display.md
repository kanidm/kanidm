
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

==== Editing attributes
Users must be able to edit attributes individually.
Users should be able to see their changes before saving them.

==== Personal Identifiable Information attributes
Certain information should not be displayed in the UI without reauthentication:
 - addresses
 - phone numbers
 - personal emails
 - birthdate

=== SSH public keys

=== Credential status
Described in [credential-display.rst](credential-display.rst)
Must inform the user of the credential update/reset page, since it is very related and might be what they were looking for instead.

=== User groups
Mostly a technical piece of info, should not be in direct view to avoid confusing users.
Could be displayed in tree form. 
