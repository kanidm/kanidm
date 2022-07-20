# Example watch control file for uscan
# Rename this file to "watch" and then you can run the "uscan" command
# to check for upstream updates and more.
# See uscan(1) for format

# Compulsory line, this is a version 4 file
version=4

# PGP signature mangle, so foo.tar.gz has foo.tar.gz.sig
#opts="pgpsigurlmangle=s%$%.sig%"

# HTTP site (basic)
#http://example.com/downloads.html \
#  files/kanidm-1.1.0-alpha.8-202207110454-([\d\.]+)\.tar\.gz debian uupdate

# Uncomment to examine an FTP server
#ftp://ftp.example.com/pub/kanidm-1.1.0-alpha.8-202207110454-(.*)\.tar\.gz debian uupdate

# SourceForge hosted projects
# http://sf.net/kanidm-1.1.0-alpha.8-202207110454/ kanidm-1.1.0-alpha.8-202207110454-(.*)\.tar\.gz debian uupdate

# GitHub hosted projects
#opts="filenamemangle=s%(?:.*?)?v?(\d[\d.]*)\.tar\.gz%<project>-$1.tar.gz%" \
#   https://github.com/<user>/kanidm-1.1.0-alpha.8-202207110454/tags \
#   (?:.*?/)?v?(\d[\d.]*)\.tar\.gz debian uupdate

# PyPI
# https://pypi.debian.net/kanidm-1.1.0-alpha.8-202207110454/kanidm-1.1.0-alpha.8-202207110454-(.+)\.(?:zip|tgz|tbz|txz|(?:tar\.(?:gz|bz2|xz)))

# Direct Git
# opts="mode=git" http://git.example.com/kanidm-1.1.0-alpha.8-202207110454.git \
#   refs/tags/v([\d\.]+) debian uupdate




# Uncomment to find new files on GooglePages
# http://example.googlepages.com/foo.html kanidm-1.1.0-alpha.8-202207110454-(.*)\.tar\.gz
