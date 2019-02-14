
Schema
------

Schema is one of the three foundational concepts of the server, along with filters and entries.
Schema defines how attribute values *must* be represented, sorted, indexed and more. It also
defines what attributes could exist on an entry.

Why Schema?
-----------

The way that the server is designed, you could extract the backend parts and just have "Entries"
with no schema. That's totally valid if you want!

However, usually in the world all data maintains some form of structure, even if loose. We want to
have ways to say a database entry represents a person, and what a person requires.

Attributes
----------

In the entry document, I discuss that avas have a single attribute, and 1 to infinite values that
are utf8 case sensitive strings. Which schema attribute types we can constrain these avas on an
entry.

For example, while the entry may be capable of holding 1 to infinite "name" values, the schema
defines that only one name is valid on the entry. Addition of a second name would be a violation. Of
course, schema also defines "multi-value", our usual 1 to infinite value storage concept.

Schema can also define that values of the attribute must conform to a syntax. For example, name
is a case *insensitive* string. So despite the fact that avas store case-sensitive data, all inputs
to name will be normalised to a lowercase form for faster matching. There are a number of syntax
types built into the server, and we'll add more later.

Finally, an attribute can be defined as indexed, and in which ways it can be indexed. We often will
want to search for "mail" on a person, so we can define in the schema that mail is indexed by the
backend indexing system. We don't define *how* the index is built - only that some index should exist
for when a query is made.

Classes
-------

So while we have attributes that define "what is valid in the avas", classes define "which attributes
can exist on the entry itself".

A class defines requirements that are "may", "must", "systemmay", "systemmust". The system- variants
exist so that we can ship what we believe are good definitions. The may and must exists so you can
edit and extend our classes with your extra attribute fields (but it may be better just to add
your own class types :) )

An attribute in a class marked as "may" is optional on the entry. It can be present as an ava, or
it may not be.

An attribute in a class marked as "must" is required on the entry. An ava that is valid to the
attribute syntax is required on this entry.

An attribute that is not "may" or "must" can not be present on this entry.

Lets imagine we have a class (pseudo example) of "person". We'll make it:

    Class {
        "name": "person",
        "systemmust": ["name"],
        "systemmay": ["mail"]
    }

If we had an entry such as:

    Entry {
        "class": ["person"],
        "uid": ["bob"],
        "mail": ["bob@email"]
    }

This would be invalid: We are missing the "systemmust" name attribute. It's also invalid because uid
is not present in systemmust or systemmay.

    Entry {
        "class": ["person"],
        "name": ["claire"],
        "mail": ["claire@email"]
    }

This entry is now valid. We have met the must requirement of name, and we have the optional
mail ava populated. The following is also valid.

    Entry {
        "class": ["person"],
        "name": ["claire"],
    }

Classes are 'additive' - this means given two classes on an entry, the must/may are unioned, and the
strongest rule is applied to attribute presence.

Imagine we have also

    Class {
        "name": "person",
        "systemmust": ["name"],
        "systemmay": ["mail"]
    }

    Class {
        "name": "emailperson",
        "systemmust": ["mail"]
    }

With our entry now, this turns the "may" from person, into a "must" because of the emailperson
class. On our entry Claire, that means this entry below is now invalid:

    Entry {
        "class": ["person", "emailperson"],
        "name": ["claire"],
    }

Simply adding an ava of mail back to the entry would make it valid once again.


