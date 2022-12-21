# Debian / Ubuntu Packaging

## Building packages

This happens in Docker currently, and here's some instructions for doing it for Ubuntu:

1. Start in the root directory of the repository.
2. Run `./platform/debian/ubuntu_docker_builder.sh` This'll start a container, mounting the
   repository in `~/kanidm/`.
3. Install the required dependencies by running `./platform/debian/install_deps.sh`.
4. Building packages uses make, get a list by running `make -f ./platform/debian/Makefile help`

```
➜ make -f platform/debian/Makefile help
debs/kanidm:
	 build a .deb for the Kanidm CLI
debs/kanidmd:
	 build a .deb for the Kanidm daemon
debs/kanidm-ssh:
	 build a .deb for the Kanidm SSH tools
debs/kanidm-unixd:
	 build a .deb for the Kanidm UNIX tools (PAM/NSS, unixd and related tools)
debs/all:
	 build all the debs
```

5. So if you wanted to build the package for the Kanidm CLI, run
   `make -f ./platform/debian/Makefile debs/kanidm`.
6. The package will be copied into the `target` directory of the repository on the docker host - not
   just in the container.

## Adding a package

There's a set of default configuration files in `packaging/`; if you want to add a package
definition, add a folder with the package name and then files in there will be copied over the top
of the ones from `packaging/` on build.

You'll need two custom files at minimum:

- `control` - a file containing information about the package.
- `rules` - a makefile doing all the build steps.

There's a lot of other files that can go into a .deb, some handy ones are:

| Filename | What it does                                                             |
| -------- | ------------------------------------------------------------------------ |
| preinst  | Runs before installation occurs                                          |
| postrm   | Runs after removal happens                                               |
| prerm    | Runs before removal happens - handy to shut down services.               |
| postinst | Runs after installation occurs - we're using that to show notes to users |

## Some Debian packaging links

- [DH reference](https://www.debian.org/doc/manuals/maint-guide/dreq.en.html) - Explains what needs
  to be done for packaging (mostly).
- [Reference for what goes in control files](https://www.debian.org/doc/debian-policy/ch-controlfields)
