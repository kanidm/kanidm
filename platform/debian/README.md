James' horrible notes about deb build things.

* DH reference: https://www.debian.org/doc/manuals/maint-guide/dreq.en.html
* [Reference for what goes in control files](https://www.debian.org/doc/debian-policy/ch-controlfields)

# Adding a thing to package

There's a set of default things in `packaging/`; if you want to add a package def, add a folder with the package name and then files in there will be copied over the top of the ones from `packaging/` on build.

You'll need two "custom" files at minimum:

- `control` - a file containing information about the package.
- `rules` - a makefile doing all the build steps.
- 