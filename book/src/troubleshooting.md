# Troubleshooting

Some things to try.

## Is the server started?

If you don't see "ready to rock! 🪨" in your logs, it's not started. Scroll back and look for
errors!

## Can you connect?

If the server's running on `idm.example.com:8443` then a simple connectivity test is done using
[curl](https://curl.se).

Run the following command:

```shell
curl https://idm.example.com:8443/status
```

This is similar to what you _should_ see:

```shell
{{#rustdoc_include troubleshooting/curl_connection_test.txt}}
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

Then either your DNS is wrong (it's pointing at 10.0.0.1) or you can't connect to the server for
some reason.

If you get errors about certificates, try adding `-k` to skip certificate verification checking and
just test connectivity:

```
curl -vk https://idm.example.com:8443/status
```

## Server things to check

- Has the config file got `bindaddress = "127.0.0.1:8443"` ? Change it to
  `bindaddress = "[::]:8443"`, so it listens on all interfaces.
- Is there a firewall on the server?
- If you're running in docker, did you expose the port (`-p 8443:8443`) or configure the network to
  host/macvlan/ipvlan?

## Client errors

When you receive a client error it will list an "Operation ID" sometimes also called the OpId or
KOpId. This UUID matches to the UUID's in the logs allowing you to precisely locate the server logs
related to the failing operation.

Try running commands with `RUST_LOG=debug` to get more information:

```shell
RUST_LOG=debug kanidm login --name anonymous
```

## Reverse Proxies not sending HTTP/1.1 requests

NGINX (and probably other proxies) send HTTP/1.0 requests by default. This'll lead to errors like this in your proxy logs:

```text
*17 upstream prematurely closed connection while reading response header from upstream, client: 172.19.0.1, server: example.com, request: "GET / HTTP/1.1", upstream: "https://172.19.0.3:8443/", host: "example.com:8443"
```

The fix for NGINX is to set the [proxy_http_version](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version) to `1.1`.

```text
proxy_http_version 1.1
```
