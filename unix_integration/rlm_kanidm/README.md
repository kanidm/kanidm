# rlm_kanidm

Rust-backed FreeRADIUS module for Kanidm authentication.

## Build

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
