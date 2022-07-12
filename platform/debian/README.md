James' horrible notes about deb build things.

* DH reference: https://www.debian.org/doc/manuals/maint-guide/dreq.en.html
* [Reference for what goes in control files](https://www.debian.org/doc/debian-policy/ch-controlfields)

# Adding a thing to package

If you want to accept the defaults in `packaging/`, go ahead. Otherwise, add a folder with the package name and then files in there will be copied over the top of the ones from `packaging/` on build.

