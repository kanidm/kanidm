James' horrible notes

* Handy: https://www.debian.org/doc/manuals/maint-guide/dreq.en.html
* No, just no: https://www.debian.org/doc/manuals/packaging-tutorial/packaging-tutorial.en.pdf

- [Reference for what goes in control files](https://www.debian.org/doc/debian-policy/ch-controlfields)

# Adding a thing to package

If you want to accept the defaults in `packaging/`, go ahead. Otherwise, add a folder with the package name and then files in there will be copied over the top of the ones from `packaging/` on build.