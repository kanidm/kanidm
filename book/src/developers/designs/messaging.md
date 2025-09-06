# Messaging

A number of features require us to be able to communicate with users. This includes things like user account signups,
credential reset requests, and notification of security events.

Each of these has unique requirements, so simply sending an email is not sufficient.

## Use Cases

This is not exhaustive, but covers some important and interesting use cases that affect our design decisions.

### User Account Signups

During an account signup, because the user is _new_, we don't have access to their mail attribute via an account object
or similar. Because of this we need to ensure that when we send mail, it doesn't collide with existing accounts who own
an email address, but also that we store the destination email in the created message object in the database (since we
have no user to refer to yet).

### Credential Reset Request

When a credential reset is requested, there are two phases of messaging we have to conduct. The first is that we need to
actually send the credential reset to the user. The second is that we should _notify_ the user at a later point in time
that the reset was requested and/or carried out. This way the user knows about the event at a later point in time in the
case that the reset was fradulent, and to a hijacked email account.

### Security Events

We should be able to email users about changes to their account, including an update of their email addresses, name or
other. In the case of an update to email addresses, we should notify the previous and new addresses of the change. Again
this necesitates that we copy the destination mail addresses to the message object, since the old address would be
removed in this situation (again, meaning we can't just refer the message object to an account which has the mail
addresses)

### Internationalisation

Many of these messages will need to be internationalised in future, so we should avoid embedding text directly in our
work, and only indicate or store "events" that can be translated to some kind of text based on user preference (like
language).

### Multiple Kani Servers

Kanidm often has multiple servers, so we need a way to ensure that messages are sent "at least once". But at the same
time we don't want to send the message _too many_ times, as this can annoy users.

### Different Messaging Requirements

Email can be a right pain, so we need to expect that users may have weird or niche email requirements when they send
messages. This means we need to try to make this somewhat extensible and detached from our server.

## Requirements

From this set of use cases we can derive a number of basic requirements.

- When we generate a message notification we need to copy the email address(es) we will send to, not relying on the
  users account details later.
- The time in which we send a message may not be "now" but delayed, so we need to ensure that we can send messages in
  the future
- Messages may need to be sent to multiple email addresses at the same time
- The text of the message should not be fixed when the event is generated, but the languages of interest to the user
  should be present, and may have multiple languages.
- We need a way to queue messages, but also indicate when the message has been dispatched by a provider.

## Design

Rather than embed messaging (email) capability into Kanidm directly, we should create an api where an external messaging
tool can consume database records from Kanidm when we wish to communicate with a user.

The database records that we generate should include:

- A generic enum indicating the type of message we want to send
- Fields that may be related to the enum of the message (such as the credential reset token)
- A datetime when the message should be sent _after_ (aka not-before)
- The set of mail addresses that the message should be sent to
- A datetime that indicates when the message was sent

This allows the external tool to do a number of things.

First, messages being an enum allows the external tool to template it's own structure of message, and customise text
etc. We can also extend this to language preferences in future too.

Second, having the datetime for sending after means that we can delay messages depending on context.

Third we copy the addresses to the message, so that even if the users email has changed, we send it to the users emails
that existed _at the time_ of message generation.

Finally, by storing when the message was sent we can allow the tool to be "somewhat" HA so that messages won't be sent
multiple times, or if there are multiple instances of the tool, they can be offset based on the message send-after date
time. For example if the primary sender is available, it will send the message almost immediately and set the datetime
of sending. But if the primary is offline the secondary can request and only send messages where the sent datetime ==
None, and the not-before is 5 to 10 minutes in the past.
