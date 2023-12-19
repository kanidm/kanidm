#!/bin/bash

PROXY_VERSION="7-debian-11"
PROXY_HTTP_PORT="10080"
PROXY_HTTPS_PORT="10443"
CLIENT_ID="test_oauth2"

# documentation for proxy settings is here: https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/overview/#environment-variables

# generate a cookie secret
echo "OAUTH2_PROXY_COOKIE_SECRET=$(openssl rand -hex 16)" > envfile
{
    echo "OAUTH2_PROXY_CLIENT_ID=${CLIENT_ID}"
    echo "OAUTH2_PROXY_CLIENT_SECRET_FILE=/opt/client.secret"
    echo "OAUTH2_PROXY_COOKIE_EXPIRE=300s"
    echo "OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256"
    echo "OAUTH2_PROXY_COOKIE_CSRF_EXPIRE=300s"
    echo "OAUTH2_PROXY_HTTP_ADDRESS=:${PROXY_HTTP_PORT}"
    echo "OAUTH2_PROXY_HTTPS_ADDRESS=:${PROXY_HTTPS_PORT}"
    echo "OAUTH2_PROXY_PROVIDER=oidc"
    echo "OAUTH2_PROXY_SCOPE=openid"
    echo "OAUTH2_PROXY_EMAIL_DOMAIN=example.com"
    echo "OAUTH2_PROXY_UPSTREAM=file://opt/index.html"
    echo "OAUTH2_PROXY_OIDC_ISSUER_URL=https://localhost:8443/oauth2/openid/${CLIENT_ID}"
    echo "OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY=true"
    # cert things, loads the certs that we use for for the test server
    echo "OAUTH2_PROXY_TLS_CERT_FILE=/opt/cert.pem"
    echo "OAUTH2_PROXY_TLS_KEY_FILE=/opt/key.pem"

    } >> envfile

if [ ! -f client.secret ]; then
    echo "The client.secret file is missing! Can't run!"
    exit 1
fi

if [ -z "$(cat client.secret)" ]; then
    echo "The client.secret file is empty! Can't run!"
    exit 1
fi

echo "#################################################################"
echo "       Starting the proxy"
echo "       Access it on https://localhost:${PROXY_HTTPS_PORT}"
echo "#################################################################"

docker run --rm -it \
    --env-file envfile \
    --network host \
    --mount "type=bind,source=/tmp/kanidm/cert.pem,target=/opt/cert.pem" \
    --mount "type=bind,source=/tmp/kanidm/key.pem,target=/opt/key.pem" \
    --mount "type=bind,source=./index.html,target=/opt/index.html" \
    --mount "type=bind,source=./client.secret,target=/opt/client.secret" \
    "bitnami/oauth2-proxy:${PROXY_VERSION}" --email-domain='*'
