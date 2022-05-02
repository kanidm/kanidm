# Metrics Development Notes

Mad keen notes bruh.

The bedrock of Kanidm is the Backend, so that's where the metrics registry lives.

Each layer of the system gets its own sub-registry, so the Backend, the QueryServer and the Idm for example each have their own sub-registries, to simplify ownership/management of metrics.