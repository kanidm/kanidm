# Getting Started

WARNING: This document is still in progress, and due to the high rate of change in the cli
tooling, may be OUT OF DATE or otherwise incorrect. If you have questions, please get
in contact!

Create the service account

    cargo run -- raw create -H https://localhost:8080 -C ../insecure/ca.pem -D admin example.create.account.json

Give it permissions

    cargo run -- raw modify -H https://localhost:8080 -C ../insecure/ca.pem -D admin '{"Or": [ {"Eq": ["name", "idm_person_account_create_priv"]}, {"Eq": ["name", "idm_service_account_create_priv"]}, {"Eq": ["name", "idm_account_write_priv"]}, {"Eq": ["name", "idm_group_write_priv"]}, {"Eq": ["name", "idm_people_write_priv"]}, {"Eq": ["name", "idm_group_create_priv"]} ]}' example.modify.idm_admin.json

Show the account details now:

    cargo run -- raw search -H https://localhost:8080 -C ../insecure/ca.pem -D admin '{"Eq": ["name", "idm_admin"]}'
    > Entry { attrs: {"class": ["account", "memberof", "object"], "displayname": ["IDM Admin"], "memberof": ["idm_people_read_priv", "idm_people_write_priv", "idm_group_write_priv", "idm_account_read_priv", "idm_account_write_priv", "idm_service_account_create_priv", "idm_person_account_create_priv", "idm_high_privilege"], "name": ["idm_admin"], "uuid": ["bb852c38-8920-4932-a551-678253cae6ff"]} }

Set the password

    cargo run -- account credential set_password -H https://localhost:8080 -C ../insecure/ca.pem -D admin idm_admin

Or even better:

    cargo run -- account credential generate_password -H https://localhost:8080 -C ../insecure/ca.pem -D admin idm_admin

Show it works:

    cargo run -- self whoami -H 'https://localhost:8080' -C ../insecure/ca.pem -D idm_admin

Now our service account can create and administer accounts and groups:

    cargo run -- raw create  -H https://localhost:8080 -C ../insecure/ca.pem -D idm_admin example.create.group.json

And of course, as the idm_admin, we can't write back to admin:

    cargo run -- account credential generate_password -H https://localhost:8080 -C ../insecure/ca.pem -D idm_admin admin

Nor can we escalate privs (we are not allow to modify HP groups):

    cargo run -- raw modify -H https://localhost:8080 -C ../insecure/ca.pem -D idm_admin '{"Eq": ["name", "idm_admins"]}' example.modify.idm_admin.json

So we have a secure way to manage the identities in the directory, without giving full control to any one account!
