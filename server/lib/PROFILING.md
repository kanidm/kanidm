# Running DHAT profiling

```shell
cargo test --features=dhat-heap test_idm_authsession_simple_password_mech

cargo install cargo-flamegraph
cargo flamegraph --root --reverse --unit-test -- 'testname'

cd ../..  # go to kanidm root directory
KANI_CARGO_OPTS="--features dhat-heap" scripts/run_insecure_dev_server.sh
```
