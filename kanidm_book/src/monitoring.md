# Monitoring the platform

The monitoring design of Kanidm is still very much in its infancy -
[take part in the dicussion at github.com/kanidm/kanidm/issues/216](https://github.com/kanidm/kanidm/issues/216).

## kanidmd

kanidmd currently responds to HTTP GET requests at the `/status` endpoint with a JSON object of
either "true" or "false". `true` indicates that the platform is responding to requests.

| URL                | `<hostname>/status`                              |
| ------------------ | ------------------------------------------------ |
| Example URL        | `https://example.com/status`                     |
| Expected response  | One of either `true` or `false` (without quotes) |
| Additional Headers | x-kanidm-opid                                    |
| Content Type       | application/json                                 |
| Cookies            | kanidm-session                                   |
