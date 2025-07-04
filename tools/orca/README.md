# Orca - A Kanidm Load Testing Tool

Make a profile.toml

```shell
orca setup-wizard --idm-admin-password ... \
  --admin-password ... \
  --control-uri 'https://localhost:8443' \
  --profile ./profile.toml
```

Test the connection

```shell
orca conntest --profile ./profile.toml
```

Generate a State File

```shell
orca generate --profile ./profile.toml --state ./state.json
```

Run the test preflight to populate the sample data

```shell
orca populate --state ./state.json
```

Run the load test

```shell
orca run --state ./state.json
```

## Design Choices

### What is a profile?

A profile defines the connection parameters and test randomisation seed. From a profile you define the parameters of the
test you wish to perform.

### What is a state file?

A statefile is the fully generated state of all entries that will be created and then used in the load test. The state
file can be recreated from a profile and it's seed at anytime. The reason to separate these is that state files may get
quite large, when what you really just need is the ability to recreate them when needed.

This state file also contains all the details about accounts and entries so that during test execution orca knows what
it can and can not interact with.

### Why have a separate generate and preflight?

Because generating the data is single thread limited, this would also bottleneck entry creation. By generating the data
first, we can then execute preflight entry creation in parallel.
