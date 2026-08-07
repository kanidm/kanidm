# Account Signup

Kanidm is going to be used in applications in future where public users need to be able to self-signup
without the intervention of an admin. We have already had multiple requests for this feature, and there
have been multiple community-indepedent implementations of this.

This now makes accounts signup an internal component of Kanidm.

## Considerations

Account signup must be opt-in for deployments.

Every deployment may have unique requirements for signup requests and how they are validated
such as:

* Email verification
* Administrator review
* Custom external application review

We need to ensure that we have flexibility to support different combinations of signup request
review so that deployments can control the process.

## Workflow

If the account signup feature flag is enabled, then the web ui will display a link to the signup form.

If the account signup feature flag is enabled, the signup form will require a user to enter the
minimal details for a new person which includes:

* username
* displayname
* email address

While email address is not a mandatory attribute in the schema today, it is required for sending
the initial credential reset request to the user account.


The form is submitted, and if the feature flag is enabled then an account signup request entry is
made with the attributes above populated. Notably, if the username or email address are not unique
then at this point an error will be returned.

The account signup flags are checked and if set engages optional behaviour.

If the email verification flag is set, an email verification email will be sent. The verification link
when clicked must show a form that requires human interaction to avoid preview-display from triggering
the verification. If the verification form is submitted an account signup request email verification
entry is created that references the uuid of the account signup request. This is so that if the
verification is done before replication has a chance to proceed, then the entry can still be created. This entry
will need to be deleted after a period of time in the case it is orphaned. (Check automatic reference entry deletion).

If administrator review flag is set, then the admin will need to manually mark the request as valid
before it can proceed.

If the custom external review flag is set, then some external tool must run and mark the request
valid via an api call. This is similar to the admin review flag.

Once all the signup flags are satisfied, the request then becomes a person account creation. At this
point the credential reset email is then sent to the user, possibly with special text to indicate that
the account creation was a success.

## Anti-spam consideration

We may limit how many account signup requests can be inflight at any one time to prevent spam. This
limit may need to be configurable.

The signup form needs CSRF and in future captcha support.

The email verification links need to use a token in the uri to assert they are valid links, rather
than just a link with a uuid embedded that triggers the validation.





