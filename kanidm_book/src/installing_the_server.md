# Installing the Server

> **NOTE** Our preferred deployment method is in containers, the documentation assumes you're running in docker. Kanidm will run in traditional compute, and server builds are available for multiple platforms, or you can build the binaries yourself if you prefer this option.

Currently we have docker images for the server components. They can be found at:

 - <https://hub.docker.com/r/kanidm/server>
 - <https://hub.docker.com/r/kanidm/radius>

You can fetch these by running the commands:

    docker pull kanidm/server:latest
    docker pull kanidm/radius:latest

If you wish to use an x86\_64 cpu-optimised version (See System Requirements CPU), you should use:

    docker pull kanidm/server:x86_64_latest

You may need to adjust your example commands throughout this document to suit.

## Development Version

If you are interested in running the latest code from development, you can do this by changing the
docker tag to `kanidm/server:devel` or `kanidm/server:x86_64_v3_devel` instead.

## System Requirements

#### CPU

If you are using the x86\_64 cpu-optimised version, you must have a CPU that is from 2013 or newer
(Haswell, Ryzen). The following instruction flags are used.

    cmov, cx8, fxsr, mmx, sse, sse2, cx16, sahf, popcnt, sse3, sse4.1, sse4.2, avx, avx2,
    bmi, bmi2, f16c, fma, lzcnt, movbe, xsave

Older or unsupported CPUs may raise a SIGIL (Illegal Instruction) on hardware that is not supported
by the project.

In this case, you should use the standard server:latest image.

In the future we may apply a baseline of flags as a requirement for x86\_64 for the server:latest
image. These flags will be:

    cmov, cx8, fxsr, mmx, sse, sse2

#### Memory

Kanidm extensively uses memory caching, trading memory consumption to improve parallel throughput.
You should expect to see 64KB of ram per entry in your database, depending on cache tuning and settings.

#### Disk

You should expect to use up to 8KB of disk per entry you plan to store. At an estimate 10,000 entry
databases will consume 40MB, 100,000 entry will consume 400MB.

For best performance, you should use non-volatile memory express (NVME), or other Flash storage media.

## TLS

You'll need a volume where you can place configuration, certificates, and the database:

    docker volume create kanidmd

You should have a chain.pem and key.pem in your kanidmd volume. The reason for requiring
Transport Layer Security (TLS, which replaces the deprecated Secure Sockets Layer, SSL) is explained in [why tls](./why_tls.md). In summary, TLS is our root of trust between the
server and clients, and a critical element of ensuring a secure system.

The key.pem should be a single PEM private key, with no encryption. The file content should be
similar to:

    -----BEGIN RSA PRIVATE KEY-----
    MII...<base64>
    -----END RSA PRIVATE KEY-----

The chain.pem is a series of PEM formatted certificates. The leaf certificate, or the certificate
that matches the private key should be the first certificate in the file. This should be followed
by the series of intermediates, and the final certificate should be the CA root. For example:

    -----BEGIN CERTIFICATE-----
    <leaf certificate>
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    <intermediate certificate>
    -----END CERTIFICATE-----
    [ more intermediates if needed ]
    -----BEGIN CERTIFICATE-----
    <ca/croot certificate>
    -----END CERTIFICATE-----

> **HINT**
> If you are using Let's Encrypt the provided files "fullchain.pem" and "privkey.pem" are already
> correctly formatted as required for Kanidm.

You can validate that the leaf certificate matches the key with the command:

    # openssl rsa -noout -modulus -in key.pem | openssl sha1
    d2188932f520e45f2e76153fbbaf13f81ea6c1ef
    # openssl x509 -noout -modulus -in chain.pem | openssl sha1
    d2188932f520e45f2e76153fbbaf13f81ea6c1ef

If your chain.pem contains the CA certificate, you can validate this file with the command:

    openssl verify -CAfile chain.pem chain.pem

If your chain.pem does not contain the CA certificate (Let's Encrypt chains do not contain the CA
for example) then you can validate with this command.

    openssl verify -untrusted fullchain.pem fullchain.pem

> **NOTE** Here "-untrusted" flag means a list of further certificates in the chain to build up
> to the root is provided, but that the system CA root should be consulted. Verification is NOT bypassed
> or allowed to be invalid.

If these verifications pass you can now use these certificates with Kanidm. To put the certificates
in place you can use a shell container that mounts the volume such as:

    docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest /bin/sh -c "cp /work/* /data/"

OR for a shell into the volume:

    docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh


# Continue on to [Configuring the Server](server_configuration.md)



