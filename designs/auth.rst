
* auth is a stepped protocol (similar to SASL)
* we offer possible authentications
* these proceed until a deny or allow is hit.

* we provide a cookie that is valid on all server instances (except read-onlies
that have unique cookie keys to prevent forgery of writable master cookies)

* cookies can request tokens, tokens are signed cbor that contains the set
of group uuids + names derferenced so that a client can make all authorisation
decisions from a single datapoint

* each token can be unique based on the type of auth (ie 2fa needed to get access
to admin groups)

