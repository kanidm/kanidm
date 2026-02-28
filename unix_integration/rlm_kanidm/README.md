# rlm_kanidm

Rust-backed FreeRADIUS module for Kanidm authentication. Here be dragons.

This is VERY much designed to be used with the container, but we're happy to accept PR's if it needs tweaking.

## Configuring it

This matches the existing configuration, reading Kanidm-specific configuration from `/data/radius.toml` in the container. The python module tried a load of different paths but this is the default going forward.

Service account auth token (the `auth_token` field) is the only way we're doing auth now, username/password is deprecated.

## Building it

Build core crate only:

```bash
cargo build -p rlm_kanidm
```

Build as a FreeRADIUS module (requires FreeRADIUS development headers and Linux target OS):

```bash
cargo build -p rlm_kanidm
```

If headers are in a non-standard path, set:

```bash
export FREERADIUS_INCLUDE_DIR=/path/to/freeradius/include
```

## Output

The shared object is:

```bash
target/debug/librlm_kanidm.so
```

For production:

```bash
cargo build -p rlm_kanidm --release --features freeradius-module
target/release/librlm_kanidm.so
```

Install it as `rlm_kanidm.so` in your FreeRADIUS module directory.

## FreeRADIUS config

See `rlm_python/mods-available/kanidm_rust` for a module config snippet.
