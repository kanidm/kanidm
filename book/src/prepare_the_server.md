# Preparing for your Deployment

## Software Installation Method

We provide docker images for the server components. They can be found at:

- <https://hub.docker.com/r/kanidm/server>
- <https://hub.docker.com/r/kanidm/radius>
- <https://hub.docker.com/r/kanidm/tools>

You can fetch these by running the commands:

```bash
docker pull kanidm/server:latest
docker pull kanidm/radius:latest
docker pull kanidm/tools:latest
```

> **NOTE** Our preferred deployment method is in containers, and this documentation assumes you're
> running in docker. Kanidm will alternately run as a daemon/service, and server builds are
> available for multiple platforms if you prefer this option. You may need to adjust the example
> commands throughout this document to suit your desired server type if you choose not to use
> containers.

## Development Version

If you are interested in running the latest code from development, you can do this by changing the
docker tag to `kanidm/server:devel` instead. Many people run the development version, and it is
extremely reliable, but occasional rough patches may occur. If you report issues, we will make every
effort to help resolve them.

## System Requirements

### CPU

Kanidm relies on modern CPU optimisations for many operations. As a result your cpu must be either:

- `x86_64` supporting `x86_64_v2` operations.
- `aarch64` supporting `neon_v8` operations.

Older or unsupported CPUs may raise a `SIGILL` (Illegal Instruction) on hardware that is not
supported by the project.

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-alert.md
imagepath=images
title=Tip
text=You can check your cpu flags on Linux with the command `lscpu`
}}

<!-- deno-fmt-ignore-end -->

#### Memory

Kanidm extensively uses memory caching, trading memory consumption to improve parallel throughput.
You should expect to see 64KB of ram per entry in your database, depending on cache tuning and
settings.

#### Disk

You should expect to use up to 8KB of disk per entry you plan to store. At an estimate 10,000 entry
databases will consume 40MB, 100,000 entry will consume 400MB.

For best performance, you should use non-volatile memory express (NVME), or other Flash storage
media.

## TLS

You'll need a volume where you can place configuration, certificates, and the database:

```bash
docker volume create kanidmd
```

You should have a chain.pem and key.pem in your kanidmd volume. The reason for requiring Transport
Layer Security (TLS, which replaces the deprecated Secure Sockets Layer, SSL) is explained in
[why tls](./frequently_asked_questions.md#why-tls). In summary, TLS is our root of trust between the
server and clients, and a critical element of ensuring a secure system.

The key.pem should be a single PEM private key, with no encryption. The file content should be
similar to:

```bash
-----BEGIN PRIVATE KEY-----
MII...<base64>
-----END PRIVATE KEY-----
```

The chain.pem is a series of PEM formatted certificates. The leaf certificate, or the certificate
that matches the private key should be the first certificate in the file. This should be followed by
the series of intermediates, and the final certificate should be the CA root. For example:

```bash
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
```

> **HINT** If you are using Let's Encrypt the provided files "fullchain.pem" and "privkey.pem" are
> already correctly formatted as required for Kanidm.

You can validate that the leaf certificate matches the key with the command:

```bash
# ECDSA
openssl ec -in key.pem -pubout | openssl sha1
1c7e7bf6ef8f83841daeedf16093bda585fc5bb0
openssl x509 -in chain.pem -noout -pubkey | openssl sha1
1c7e7bf6ef8f83841daeedf16093bda585fc5bb0

# RSA
# openssl rsa -noout -modulus -in key.pem | openssl sha1
d2188932f520e45f2e76153fbbaf13f81ea6c1ef
# openssl x509 -noout -modulus -in chain.pem | openssl sha1
d2188932f520e45f2e76153fbbaf13f81ea6c1ef
```

If your chain.pem contains the CA certificate, you can validate this file with the command:

```bash
openssl verify -CAfile chain.pem chain.pem
```

If your chain.pem does not contain the CA certificate (Let's Encrypt chains do not contain the CA
for example) then you can validate with this command.

```bash
openssl verify -untrusted fullchain.pem fullchain.pem
```

> **NOTE** Here "-untrusted" flag means a list of further certificates in the chain to build up to
> the root is provided, but that the system CA root should be consulted. Verification is NOT
> bypassed or allowed to be invalid.

If these verifications pass you can now use these certificates with Kanidm. To put the certificates
in place you can use a shell container that mounts the volume such as:

```bash
docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest \
    /bin/sh -c "cp /work/* /data/"
```

OR for a shell into the volume:

```bash
docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh
```
