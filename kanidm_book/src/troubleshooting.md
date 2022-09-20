# Troubleshooting

Some things to try.

## Is the server started?

If you don't see "ready to rock! 🪨" in your logs, it's not started. Scroll back and look for errors!dd

## Can you connect?

If the server's running on `idm.example.com:8443` then a simple connectivity test is done using [curl](https://curl.se).

Run the following command:
```shell
curl -k https://idm.example.com:8443/status
```

This is similar to what you *should* see:

```
➜ curl -vk https://idm.example.com:8443/status
*   Trying 10.0.0.14:8443...
* Connected to idm.example.com (10.0.0.14) port 8443 (#0)
* successfully set certificate verify locations:
*  CAfile: /etc/ssl/cert.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-ECDSA-AES256-GCM-SHA384
* Server certificate:
*  subject: C=AU; ST=Queensland; L=Brisbane; O=INSECURE EXAMPLE; OU=kanidm; CN=idm.example.com
*  start date: Sep 20 09:28:18 2022 GMT
*  expire date: Oct 21 09:28:18 2022 GMT
*  SSL certificate verify result: self signed certificate in certificate chain (19), continuing anyway.
> GET /status HTTP/1.1
> Host: idm.example.com:8443
> User-Agent: curl/7.79.1
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< cache-control: no-store, max-age=0
< content-length: 4
< content-type: application/json
< date: Tue, 20 Sep 2022 11:52:23 GMT
< pragma: no-cache
< set-cookie: kanidm-session=+LQJKwL0UdAEMoTc0Zrgne2hU+N2nB+Lcf+J1OoI9n4%3DNE7xuL9yCq7B0Ai+IM3gq5T+YZ0ckDuDoWZKzhPMHmSk3oFSscp9vy9n2a5bBFjWKgeNwdLzRbYc4rvMqYi11A%3D%3D; HttpOnly; SameSite=Strict; Secure; Path=/; Expires=Wed, 21 Sep 2022 11:52:23 GMT
< x-content-type-options: nosniff
< x-kanidm-opid: 8b25f050-7f6e-4ce1-befe-90be3c4f8a98
<
* Connection #0 to host localhost left intact
true
```

This means:

1. you've successfully connected to a host (10.0.0.14),
2. TLS worked
3. Received the status response "true"

If you see something like this:

```
➜ curl -v https://idm.example.com:8443
*   Trying 10.0.0.1:8443...
* connect to 10.0.0.1 port 8443 failed: Connection refused
* Failed to connect to idm.example.com port 8443 after 5 ms: Connection refused
* Closing connection 0
curl: (7) Failed to connect to idm.example.com port 8443 after 5 ms: Connection refused
```

Then either your DNS is wrong (it's pointing at 10.0.0.1) or you can't connect to the server for some reason.

If you get errors about certificates, try adding `-k` to skip certificate verification checking and just test connectivity:

```
curl -vk https://idm.example.com:8443
```

## Server things to check

* Has the config file got `bindaddress = "127.0.0.1:8443"` ? Change it to `bindaddress = "[::]:8443"`, so it listens on all interfaces.
* Is there a firewall on the server?
* If you're running in docker, did you expose the port? (`-p 8443:8443`)

## Client things to check

Try running commands with `RUST_LOG=debug` to get more information:

```
RUST_LOG=debug kanidm login --name anonymous
```

