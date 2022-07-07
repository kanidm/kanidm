# Domain Display Name

A human-facing string to use in places like web page titles, TOTP issuer codes, the Oauth  authorisation server name etc.

On system creation, or if it hasn't been set, it'll default to `format!("Kanidm {}", domain_name)` so that you'll see `Kanidm idm.example.com` if your domain is `idm.example.com`.

