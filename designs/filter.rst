
Filters
-------

Filters (along with Entries and Schema) is one of the foundational concepts in the
design of KaniDM. They are used in nearly every aspect of the server to provide
checking and searching over entry sets.

A filter is a set of requirements where the attribute-value pairs of the entry must
conform for the filter to be considered a "match". This has two useful properties:

* We can apply a filter to a single entry to determine quickly assertions about that entry
hold true.
* We can apply a filter to a set of entries to reduce the set only to the matching entries.

Filter Construction
-------------------

Filters are rooted in relational algebra and set mathematics. I am not an expert on either
topic, and have learnt from experience about there design.

* Presence

The simplest filter is a "presence" test. It asserts that some attribute, regardless
of it's value exists on the entry. For example, the entries below:

    Entry {
        name: william
    }

    Entry {
        description: test
    }

If we apply "Pres(name)", then we would only see the entry containing "name: william" as a matching
result.

* Equality

Equality checks that an attribute and value are present on an entry. For example

    Entry {
        name: william
    }

    Entry {
        name: test
    }

If we apply Eq(name, william) only the first entry would match. If the attribute is multivalued,
we only assert that one value in the set is there. For example:

    Entry {
        name: william
    }

    Entry {
        name: test
        name: claire
    }

In this case application of Eq(name, claire), would match the second entry as name=claire is present
in the multivalue set.

* Sub

Substring checks that the substring exists in an attribute of the entry. This is a specialisation
of equality, where the same value and multivalue handling holds true.

    Entry {
        name: william
    }

In this example, Sub(name, liam) would match, but Sub(name, air) would not.

* Or

Or contains multiple filters and asserts that provided *any* of them are true, this condition
will hold true. For example:

    Entry {
        name: claire
    }

In this the filter Or(Eq(name, claire), Eq(name, william)) will be true, because the Eq(name, claire)
is true, thus the Or condition is true. If nothing inside the Or is true, it returns false.

* And

And checks that all inner filter conditions are true, to return true. If any are false, it will
yield false.

    Entry {
        name: claire
        class: person
    }

For this example, And(Eq(class, person), Eq(name, claire)) would be true, but And(Eq(class, group),
Eq(name, claire)) would be false.

* AndNot

AndNot is different to a logical not.

If we had Not(Eq(name, claire)), then the logical result is "All entries where name is not
claire". However, this is (today...) not very efficient. Instead, we have "AndNot" which asserts
that a condition of a candidate set is not true. So the operation: AndNot(Eq(name, claire)) would
yield and empty set. AndNot is important when you need to check that something is also not true
but without getting all entries where that not holds. An example:

    Entry {
        name: william
        class: person
    }

    Entry {
        name: claire
        class: person
    }

In this case "And(Eq(class, person), AndNot(Eq(name, claire)))". This would find all persons
where their name is also not claire: IE william. However, the following would be empty result.
"AndNot(Eq(name, claire))". This is because there is no candidate set already existing, so there
is nothing to return.


Filter Schema Considerations
----------------------------

In order to make filters work properly, the server normalises entries on input to allow simpler
comparisons and ordering in the actual search phases. This means that for a filter to operate
it too must be normalised an valid.

If a filter requests an operation on an attribute we do not know of in schema, the operation
is rejected. This is to prevent a denial of service attack where Eq(NonExist, value) would cause
un-indexed full table scans to be performed consuming server resources.

In a filter request, the Attribute name in use is normalised according to schema, as it
the search value. For example, Eq(nAmE, Claire) would normalise to Eq(name, claire) as both
attrname and name are UTF8_INSENSITIVE. However, displayName is case sensitive so a search like:
Eq(displayName, Claire) would become Eq(displayname, Claire). Note Claire remains cased.

This means that instead of having costly routines to normalise entries on each read and search,
we can normalise on entry modify and create, then we only need to ensure filters match and we
can do basic string comparisons as needed.


Discussion
----------

Is it worth adding a true "not" type, and using that instead? It would be extremely costly on
indexes or filter testing, but would logically be better than AndNot as a filter term.

Not could be implemented as Not(<filter>) -> And(Pres(class), AndNot(<filter>)) which would
yield the equivalent result, but it would consume a very large index component. In this case
though, filter optimising would promote Eq > Pres, so we would should be able to skip to a candidate
test, or we access the index and get the right result anyway over fulltable scan.

Additionally, Not/AndNot could be security risks because they could be combined with And
queries that allow them to bypass the filter-attribute permission check. Is there an example
of using And(Eq, AndNot(Eq)) that could be used to provide information disclosure about
the status of an attribute given a result/non result where the AndNot is false/true?

