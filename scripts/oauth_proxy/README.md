# OAuth Proxy Test

This dir has some things for setting up a simple OAuth2 RS so things can get tested.

## Quick Setup

1. Run the `setup_dev_environment.sh` script and set a credential for `testuser`.
2. Look for `Pulling secret for the OAuth2 RP` in the script output and grab the secret, putting it in a `client.secret` file in this dir.
3. Run `./run_proxy.sh` to start the proxy, and then go to the URL and do the thing!
