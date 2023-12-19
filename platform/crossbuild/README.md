# Cross-building things using cargo cross

Here be dragons.

1. Get a drink. You'l need it.
2. Install [cargo-cross](https://github.com/cross-rs/cross)
3. Drink the drink.

## Building Ubuntu 20.04 things

Make sure you're including `--release` because reasons.

```shell
CROSS_CONFIG=platform/crossbuild/ubuntu-20.04/Cross.toml \
    cross build --target aarch64-unknown-linux-gnu \
        --bin kanidm_unixd \
        --bin kanidm_unixd_tasks \
        --bin kanidm_ssh_authorizedkeys \
        --bin kanidm-unix \
        --release
```

Things will end up in `./target/aarch64-unknown-linux-gnu/release/`

## Building Ubuntu 22.04 things

Make sure you're including `--release` because reasons.

```shell
CROSS_CONFIG=platform/crossbuild/ubuntu-22.04/Cross.toml \
    cross build --target aarch64-unknown-linux-gnu \
        --bin kanidm_unixd \
        --bin kanidm_unixd_tasks \
        --bin kanidm_ssh_authorizedkeys \
        --bin kanidm-unix \
        --release
```

Things will end up in `./target/aarch64-unknown-linux-gnu/release/`
