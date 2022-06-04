# kanidm_rlm_python

A FREERadius kanidm client module per the [module docs](https://wiki.freeradius.org/modules/Rlm_python).

** NOTE ** These docs are in development, sorry.

Testing Process
===============

    cd kanidmd
    cargo run -- recover_account -c ./server.toml -n admin
    cargo run -- server -c ./server.toml



    cd kanidm_tools
    cargo run -- login -D admin
    cargo run -- account list -D admin
    cargo run -- account create -D admin radius_service_account radius_service_account
    cargo run -- group add_members -D admin idm_radius_servers radius_service_account
    cargo run -- account credential set_password radius_service_account -D admin
    cargo run -- account radius generate_secret admin -D admin

    cd kanidm_rlm_python/
    KANIDM_RLM_CONFIG=./test_data/config.ini python3 kanidmradius.py test
    KANIDM_RLM_CONFIG=./test_data/config.ini python3 kanidmradius.py admin





