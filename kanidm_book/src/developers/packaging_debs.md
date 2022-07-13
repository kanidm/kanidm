# Debian / Ubuntu Packaging

## Adding a package

There's a set of default configuration files in `packaging/`; if you want to add a package definition, add a folder with the package name and then files in there will be copied over the top of the ones from `packaging/` on build.

You'll need two custom files at minimum:

- `control` - a file containing information about the package.
- `rules` - a makefile doing all the build steps.

There's a lot of other files that can go into a .deb, some handy ones are:

| Filename | What it does                                                             |
| ---      | ---                                                                      |
| preinst  | Runs before installation occurs                                          |
| postrm   | Runs after removal happens                                               |
| prerm    | Runs before removal happens - shut down services etc                     |
| postinst | Runs after installation occurs - we're using that to show notes to users |


## Some Debian packaging links

* [DH reference](https://www.debian.org/doc/manuals/maint-guide/dreq.en.html) - Explains what needs to be done for packaging (mostly).
* [Reference for what goes in control files](https://www.debian.org/doc/debian-policy/ch-controlfields)