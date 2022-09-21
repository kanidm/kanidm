
# Why TLS?

You may have noticed that Kanidm requires you to configure TLS in your container.

We are a secure-by-design rather than secure-by-installation system, so TLS for 
all connections is considered mandatory.

## What are Secure Cookies?

`secure-cookies` is a flag set in cookies that asks a client to transmit them
back to the origin site if and only if HTTPS is present in the URL.

Certificate authority (CA) verification is *not* checked - you can use invalid, 
out of date certificates, or even certificates where the `subjectAltName` does 
not match, but the client must see https:// as the destination else it *will not* 
send the cookies.

## How Does That Affect Kanidm?

Kanidm's authentication system is a stepped challenge response design, where you
initially request an "intent" to authenticate. Once you establish this intent,
the server sets up a session-id into a cookie, and informs the client of
what authentication methods can proceed.

If you do NOT have a HTTPS URL, the cookie with the session-id is not transmitted. 
The server detects this as an invalid-state request in the authentication design, 
and immediately breaks the connection, because it appears insecure.

Simply put, we are trying to use settings like `secure_cookies` to add constraints
to the server so that you *must* perform and adhere to best practices - such
as having TLS present on your communication channels.
