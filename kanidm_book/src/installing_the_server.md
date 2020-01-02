# Installing the Server

Currently we have a pre-release docker image based on git master. They can be found at:

    https://hub.docker.com/r/firstyear/kanidmd
    https://hub.docker.com/r/firstyear/kanidm_radius

You'll need a volume where you can put certificates and the database:

    docker volume create kanidmd

You should have a ca.pem, cert.pem and key.pem in your kanidmd volume. The reason for requiring
TLS is explained in [why tls](./why_tls.md) . To put the certificates in place you can use a shell container
that mounts the volume such as:

    docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest cp /work/* /data/
    OR for a shell into the volume:
    docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh

Then you can setup the initial admin account and initialise the database into your volume.

    docker run --rm -i -t -v kanidmd:/data firstyear/kanidmd:latest /sbin/kanidmd recover_account -D /data/kanidm.db -n admin

You then want to set your domain name so that spn's are generated correctly.

    docker run --rm -i -t -v kanidmd:/data firstyear/kanidmd:latest /sbin/kanidmd domain_name_change -D /data/kanidm.db -n idm.example.com

Now we can run the server so that it can accept connections.

    docker run -p 8443:8443 -v kanidmd:/data firstyear/kanidmd:latest

