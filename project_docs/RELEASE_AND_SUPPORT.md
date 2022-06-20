## Release Schedule

In the alpha phase, Kanidm will be released on a 3 month (quarterly) basis,
starting on July 1st 2020.

* February 1st
* May 1st
* August 1st
* November 1st

Releases will be tagged and branched in git.

1.2.0 will be released as the first supported version once the project believes the project is
in a maintainable longterm state, without requiring backward breaking changes. There is no current
estimated date for 1.2.0.

## Support

Releases during alpha will not recieve fixes or improvements once released, with the exception of:

* Major security issues
* Flaws leading to dataloss or corruption
* Other fixes at the discrestion of the project team

In the case these issues are found, an out of band alpha snapshot will be made based on the current
stable branch.

Alpha releases are "best effort", and are trial releases, to help get early feedback and improvements
from the community, while still allowing us to make large, breaking changes that may be needed.

## API stability

There are a number of "surfaces" that can be considered as "API" in Kanidm.

* JSON HTTP end points of kanidmd
* unix domain socket API of `kanidm_unixd` resolver
* LDAP interface of kanidm
* CLI interface of kanidm admin command
* Many other interaction surfaces

During the Alpha, there is no guarantee that *any* of these APIs named here or not named will remain stable.
Only elements from "the same release" are guaranteed to work with each other.

Once an official release is made, only the JSON API and LDAP interface will be declared stable.

The unix domain socket API is internal and will never be "stable".

The CLI is *not* an API and can change with the interest of human interaction during any release.

## Python module

The python module will typically trail changes in functionality of the core Rust code, and will be developed as we it for our own needs - please feel free to add functionality or improvements, or [ask for them in a Github issue](http://github.com/kanidm/kanidm/issues/new/choose)!

All code changes will include full type-casting wherever possible.
