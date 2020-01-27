
# Why TLS?

You may have noticed that Kanidm requires you to configure TLS in
your container - or that you provide something *with* TLS in front like haproxy.

This is due to a single setting on the server - `secure_cookies`

## What are Secure Cookies?

`secure-cookies` is a flag set in cookies that "asks" a client to transmit them
back to the origin site if and only if https is present in the URL.

CA verification is *not* checked - you can use invalid, out of date certificates,
or even certificates where the `subjectAltName` does not match, but the client
must see https:// as the destination else it *will not* send the cookies.

## How does that affect Kanidm?

Kanidm's authentication system is a stepped challenge response design, where you
initially request an "intent" to authenticate. Once you establish this intent,
the server sets up a session-id into a cookie, and informs the client of
what authentication methods can proceed.

When you then go to continue the authentication, if you do NOT have a https url,
the cookie with the session-id is not transmitted. The server detects this as
an invalid-state request in the authentication design and immediately disconnects
you from attempting to continue the authentication as you may be using an insecure
channel.

Simply put, we are trying to use settings like secure_cookies to add constraints
to the server so that you *must* perform and adhere to best practices - such
as having TLS present on your communication channels.
