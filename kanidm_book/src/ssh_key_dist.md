# SSH Key Distribution

To support SSH authentication securely to a large set of hosts running SSH, we support distribution
of SSH public keys via the kanidm server.

## pre-release warning

Currently the tools involved on the client machines do *not* cache the SSH public keys. This means
that if your primary kanidm server is offline you will *not* be able to SSH to these machines. You
should adapt and maintain a disaster recovery plan that allows you to access machines if or when
this situation occurs.

## Configuring accounts

To view the current ssh public keys on accounts, you can use:

    kanidm account ssh list_publickeys --name <login user> <account to view>
    kanidm account ssh list_publickeys --name idm_admin william

All users by default can self-manage their ssh public keys. To upload a key, a command like this
is the best way to do so:

    kanidm account ssh add_publickey --name william william 'test-key' "`cat ~/.ssh/id_rsa.pub`"

To remove (revoke) an ssh publickey, you delete them by the tag name:

    kanidm account ssh delete_publickey --name william william 'test-key'

## Security notes

As a security feature, kanidm validates *all* publickeys to ensure they are valid ssh publickeys.
Uploading a private key or other data will be rejected. For example:

    kanidm account ssh add_publickey --name william william 'test-key' "invalid"
    Enter password:
    thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: Http(400, Some(SchemaViolation(InvalidAttributeSyntax)))', src/libcore/result.rs:1084:5

## Server Configuration

The kanidm_ssh_authorizedkeys command is part of the kanidm-clients package, so should be installed
on the servers.

To configure the tool, you should edit /etc/kanidm/config, as documented in [clients](./client_tools.md)

You can test this is configured correctly by running:

    kanidm_ssh_authorizedkeys -D anonymous <account name>

If the account has ssh public keys you should see them listed, one per line.

To configure servers to accept these keys, you must change their /etc/ssh/sshd_config to
contain the lines:

    AuthorizedKeysCommand /usr/bin/kanidm_ssh_authorizedkeys -D anonymous %u
    AuthorizedKeysCommandUser nobody

Restart sshd, and then attempt to authenticate with the keys.

It's highly recommended you keep your client configuration and sshd_configuration in a configuration
management tool such as salt or ansible.
