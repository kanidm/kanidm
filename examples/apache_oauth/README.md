# Apache OAuth config example

This example is here mainly for devs to come up with super complicated ways to test the changes
they're making which affect OAuth things.

## Example of how to run it

```shell
OAUTH_HOSTNAME=test-oauth2.example.com \
KANIDM_HOSTNAME=test-kanidm.example.com \
KANIDM_CLIENT_SECRET=1234Hq5d1J5GG9VNae3bRMFGDVFR3bUyyXg3RPRSefJLNhee \
KANIDM_PORT=443 \
make
```

This'll build and run the docker container.
