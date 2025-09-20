# Packages

This chapter presents the alternative packages and how to build your own.

To ease packaging for your distribution, the `Makefile` has targets for sets of binary outputs.

| Target                 | Description                 |
| ---------------------- | --------------------------- |
| `release/kanidm`       | Kanidm's CLI                |
| `release/kanidmd`      | The server daemon           |
| `release/kanidm-ssh`   | SSH-related utilities       |
| `release/kanidm-unixd` | UNIX tools, PAM/NSS modules |

## Community Packages

There are several community maintained packages that you may use in your system. However, they are not officially
supported and may not function identically.

- [Alpine Linux](https://pkgs.alpinelinux.org/packages?name=kanidm%2A)
- [Arch Linux](https://aur.archlinux.org/packages?O=0&K=kanidm)
- [Debian / Ubuntu](debian_ubuntu_packaging.md)
- [NixOS](https://search.nixos.org/packages?sort=relevance&type=packages&query=kanidm)
- [OpenSUSE](https://software.opensuse.org/search?baseproject=ALL&q=kanidm)
