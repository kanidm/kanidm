
# Accounts and groups

The system admin account (the account you recovered in the setup) has limited privileges - only to
manage high-privilege accounts and services. This is to help seperate system administration
from identity administration actions.

## Creating an IDM Admin account

You should generate a secure password for the idm_admin account now, by using the admin account to
reset that credential.

    cargo run -- account credential generate_password -H ... --name admin idm_admin
    Generated password for idm_admin: tqoReZfz....

It's a good idea to use the "generate_password" for high security accounts due to the strong
passwords generated.

We can now use the idm_admin to create groups and accounts.

    cargo run -- group create radius_access_allowed -H ... --name idm_admin
    cargo run -- account create demo_user "Demonstration User" -H ... --name idm_admin
    cargo run -- group add_members radius_access_allowed demo_user -H ... --name idm_admin
    cargo run -- group list_members radius_access_allowed -H ... --name idm_admin
    cargo run -- account get demo_user -H ... --name idm_admin

You can also use anonymous to view users and groups - note that you won't see as many fields due
to the different anonymous access profile limits!

    cargo run -- account get demo_user -H ... --name anonymous

Finally, performa a password reset on the demo_user - we'll be using them from now to show how
accounts can be self sufficent.

    cargo run -- account credential set_password demo_user -H ... --name idm_admin
    cargo run -- self whoami -H ... --name demo_user

