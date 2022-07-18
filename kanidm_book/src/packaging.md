# Packaging

Packages are known to exist for the following distributions:

 - [Arch Linux](https://aur.archlinux.org/packages?O=0&K=kanidm)
 - [OpenSUSE](https://software.opensuse.org/search?baseproject=ALL&q=kanidm)
 - [NixOS](https://search.nixos.org/packages?sort=relevance&type=packages&query=kanidm)

To ease packaging for your distribution, the `Makefile` has targets for sets of binary outputs.
  
|       Target           |      Description            |
|        ---             |         ---                 |
| `release/kanidm`       | Kanidm's CLI                |
| `release/kanidmd`      | The server daemon           |
| `release/kanidm-ssh`   | SSH-related utilities       |
| `release/kanidm-unixd` | UNIX tools, PAM/NSS modules |
