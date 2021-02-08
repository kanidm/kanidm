unixd homes task
----------------

Kanidm attempts to promote uuid's as the primary foreign key that should be
used by applications. A classic feature of pam and nsswitch tools is to create
the home directory of the account on first login.

Because of these two things, we previously would have to ask deployments to chose between
the follow attributes for home directory names.

* uuid - the preferred foreign key, but not user-friendly.
* name/spn - user friendly, but will break on account rename.

The unixd tasks daemon is inspired by oddjobd, and allows us to create home directories
with awareness of this problem.

home directory design
---------------------

On login, the tasks daemon uses the value of "home_attr" as the name of the
home directory/folder. If present, the value of "home_alias" is used in getent
responses, and a symlink from "home_alias" is made to home attr. For example:

::

    home_attr = uuid

    getent passwd <id>
    home = /home/6a159739-93f0-4bff-bdfb-6044c1bab55c

    /home/6a159739-93f0-4bff-bdfb-6044c1bab55c


::

    home_attr = uuid
    home_alias = spn

    getent passwd <id>
    home = /home/<id>@<domain>

    /home/6a159739-93f0-4bff-bdfb-6044c1bab55c
    /home/<id>@<domain> -> /home/6a159739-93f0-4bff-bdfb-6044c1bab55c

This allows us to flip the symlink on logins if id/domain is ever changed, with
out losing or breaking the content of the home directory. 

tasks daemon design
-------------------

The current unixd daemon runs as an isolated and unprivileged user. This is so that pam/nss
contact the unixd daemon and that performs network access on their behalf. due to this
design, this limits damage in a compromise as the unixd daemon is not-root, and has limited
channels to other processes.

However, to create home directories, this requires root permissions to perform the tasks.

An extra daemon is created that carries this out. This is the unixd-tasks daemon. As this runs
as root, the tasks daemon an attractive target for "bad people" ™ so careful design around
the security of this is required.

::

    ┌───────────────┐                                                       
    │      Pam      │    /var/run/kanidm-unixd/sock                         
    │               │───────────┐(mode 777)                                 
    └───────────────┘           │                                           
                                │           ┌──────────────────────────────┐
                                │           │            Unixd             │
                                ├──────────▶│       (isolated user)        │
     ┌──────────────┐           │           └──────────────────────────────┘
     │   Nsswitch   │           │                           ▲               
     │              │───────────┘                           │               
     └──────────────┘                                       │               
                                                            │               
                           /var/run/kanidm-unixd/tasks-sock │               
                               (mode 600, isolated user)    │               
                                                            │               
                                                            │               
                                                 ┌─────────────────────┐    
                                                 │     Unixd Tasks     │    
                                                 │       (root)        │    
                                                 └─────────────────────┘    


The tasks daemon runs as root and has no network facing elements. It connects to the
unixd daemon via a protected unix socket. The unixd daemon established a listening
socket that only root or itself can access at /var/run/kanidm-unixd/tasks-sock which
the unixd tasks daemon connects to. This is because with systemd dynamic users
the tasks daemon may not know what user account it has to chown sockets to, so it is
not viable for the tasks daemon to create the listening socket with the correct permissions.
This is especially true if the unixd daemon restarts and acquires a new uid, while the tasks
daemon persists.

The tasks daemon only recieves a single datagram, which informs it of the details of
the path and symlinks to create. The daemon filters for a number of path injection attacks
that may be present in the names of the accounts. The Kanidm server also filters for path injections in
usernames.

The unixd daemon maintains a work queue that it ships to the tasks daemon. This queue is
bounded and if the queue is not being serviced, it proceeds with the login/process
as we must assume the user has *not* configured the tasks daemon on the system. This queue
also prevents memory growth/ddos if we are overloaded by login requests.

In packaging the tasks daemon will use systemds isolation features to further harden this. For
example:

::

    CapabilityBoundingSet=CAP_CHOWN,CAP_FOWNER
    SystemCallFilter=@aio @basic-io @chown @file-system @io-event @network-io @sync
    ProtectSystem=strict
    ReadWritePaths=/home /var/run/kanidm-unixd
    RestrictAddressFamilies=AF_UNIX
    NoNewPrivileges=true
    PrivateTmp=true
    PrivateDevices=true
    PrivateNetwork=true
    ProtectHostname=true
    ProtectClock=true
    ProtectKernelTunables=true
    ProtectKernelModules=true
    ProtectKernelLogs=true
    ProtectControlGroups=true
    MemoryDenyWriteExecute=true



// todo, should be added to unixd
# ProtectHome=¶

    
