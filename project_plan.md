# Project: Rewrite rlm_python in Rust (draft)

## Project description
Kanidm has support for RADIUS. RADIUS is a service that provides authentication, authorization and management of users that wish to access WLANs or VPNs.

When a user wants to access a WLAN (or VPN) from their device, they submit an username and a password to the NAS. The NAS then sends an access-request with the user's credentials to the RADIUS server. The RADIUS server communicates with the Kanidm server to retrieve the user's RADIUS credentials and other information required for authorization. If the credentials match and the user can be authorized, the RADIUS server sends an access-accept back to the NAS, which finally allows the user's device to access the network.

The RADIUS server is configured to communicate with the Kanidm server through a RADIUS loadable module (RLM), which is a way for the RADIUS server to run custom scripts when it receives requests. RADIUS has support for Python RLMs. Kanidm provides a Docker image for the RADIUS server that includes a RLM written in Python for operating with the Kanidm server.

The goal of the project is to add support for Rust RLMs and to rewrite the current Kanidm Python RLM in Rust. An implementation of RADIUS is freeradius, which is written in C. Therefore, Rust RLM support requires FFIs to the freeradius C source code. The rewrite would allow for writing RLMs in Rust.

Kanidm also provides a Python package (pykanidm) for Kanidm clients, which the Kanidm Python RLM uses. A possibility is to rewrite pykanidm in Rust.

## Project plan
A RLM defines custom scripts for various RADIUS activities. The Kanidm Python RLM currently defines custom scripts for instantiation of the RADIUS server, authentication of users, and authorization of users. A starting point would then be to add Rust RLM support and to rewrite the Python RLM in Rust with support for customizing scripts for these three activities. Afterwards, support for the remaining RADIUS activities can be considered.

### Project plan steps
1. Research how RADIUS calls the Kanidm Python RLM and which RADIUS functions need to be interfaced with to support Rust RLMs. Also look into how RLM custom scripts are structured as to be a valid RLM script.

2. Plan a setup which is viable for testing while performing the rewrite.

3. Start implementing support for the three RADIUS activities used by Kanidm as mentioned in the project description.

4. Connect RADIUS to Kanidm such that the RLM funcionality that Kanidm uses can be tested. Perhaps pykanidm should also be rewritten in Rust?

5. Continue implementing support for the remaining RADIUS features?

6. ?