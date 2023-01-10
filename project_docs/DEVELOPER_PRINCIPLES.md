# Developer Principles

As a piece of software that stores the identities of people, the project becomes bound to social and
political matters. The decisions we make have consequences on many people - many who never have the
chance to choose what software is used to store their identities (think employees in a business).

This means we have a responsibility to not only be aware of our impact on our direct users
(developers, system administrators, dev ops, security and more) but also the impact on indirect
consumers - many of who are unlikely to be in a position to contact us to ask for changes and help.

## Ethics / Rights

If you have not already, please see our documentation on [rights and ethics]

[rights and ethics]: https://github.com/kanidm/kanidm/blob/master/ethics/README.md

## Humans First

We must at all times make decisions that put humans first. We must respect all cultures, languages,
and identities and how they are represented.

This may mean we make technical choices that are difficult or more complex, or different to "how
things have always been done". But we do this to ensure that all people can have their identities
stored how they choose.

For example, any user may change their name, display name and legal name at any time. Many
applications will break as they primary key from name when this occurs. But this is the fault of the
application. Name changes must be allowed. Our job as technical experts is to allow that to happen.

We will never put a burden on the user to correct for poor designs on our part. For example, locking
an account if it logs in from a different country unless the user logs in before hand to indicate
where they are going. This makes the user responsible for a burden (changing the allowed login
country) when the real problem is preventing bruteforce attacks - which can be technically solved in
better ways that don't put administrative load to humans.

## Correct and Simple

As a piece of security sensitive software we must always put correctness first. All code must have
tests. All developers must be able to run all tests on their machine and environment of choice.

This means that the following must always work:

```bash
git clone ...
cargo test
```

If a test or change would require extra requirements, dependencies, or preconfiguration, then we can
no longer provide the above. Testing must be easy and accessible, else we won't do it, and that
leads to poor software quality.

The project must be simple. Any one should be able to understand how it works and why those
decisions were made.

## Languages

The core server will (for now) always be written in Rust. This is due to the strong type guarantees
it gives, and how that can help raise the quality of our project.

## Over-Configuration

Configuration will be allowed, but only if it does not impact the statements above. Having
configuration is good, but allowing too much (IE a scripting engine for security rules) can give
deployments the ability to violate human first principles, which reflects badly on us.

All configuration items, must be constrained to fit within our principles so that every kanidm
deployment, will always provide a positive experience to all people.
