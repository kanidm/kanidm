# Packaging

This chapter presents the alternative packages and how to build your own.

To ease packaging for your distribution, the `Makefile` has targets for sets of binary outputs.

| Target                 | Description                 |
| ---------------------- | --------------------------- |
| `release/kanidm`       | Kanidm's CLI                |
| `release/kanidmd`      | The server daemon           |
| `release/kanidm-ssh`   | SSH-related utilities       |
| `release/kanidm-unixd` | UNIX tools, PAM/NSS modules |
