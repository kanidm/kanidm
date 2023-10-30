# OAuth Proxy Test

This dir has some things for setting up a simple OAuth2 RS so things can get tested.

## Quick Setup

1. Run the `setup_dev_environment.sh` script and set a credential for `testuser`.
2. Look for the OAuth2 Secret in the script output and copy it into a file called `client.secret` in
   this dir.
3. Run `./run_proxy.sh` to start the proxy, and then go to the URL and do the thing!
