## Release Schedule

In the alpha phase, kanidm will be released on a 3 month (quarterly) basis,
starting on July 1st 2020.

* January 1st
* April 1st
* July 1st
* October 1st

Releases will be tagged in git, but not maintained as branches.

1.2.0 will be released as the first supported version once the project believes the project is
in a maintainable longterm state, without requiring backward breaking changes. There is no current
estimated date for 1.2.0.

## Support

Releases during alpha will not recieve fixes or improvements once released, with the exception of:

* Major security issues
* Flaw leading to dataloss or corruption

In the case these issues are found, an out of band alpha snapshot will be made.

Alpha releases are "best effort", and are trial releases, to help get early feedback and improvements
from the community, while still allowing us to make large, breaking changes that may be needed.

## API stability

There are a number of "surfaces" that can be considered as "API" in Kanidm.

* JSON HTTP end points of kanidmd
* unix domain socket API of kanidm_unixd resolver
* CLI interface of kanidm admin command

During the Alpha, there is no guarantee that *any* of these APIs will remain stable. Only elements from "the same release" are guaranteed to work with each other.

Once an official release is made, only the JSON API will be declared stable. The unix domain socket API is internal, and the CLI is *not* an API and can change with the interest of human interaction during any release.

