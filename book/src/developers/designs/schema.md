# Schema Changes 2024 / 2025

Our current schema structure has served us very well, remaining almost unchanged since nearl 2018.

The current design is a heavily adapted LDAP/AD style structure with classes that define a set
of may and must attributes, and attributes that define properties like single value, multivalue,
the types of indexes to apply, and the syntax of the attribute.

However, after 6 years we are starting to finally run into some limits.

## Proposed Changes

### Removal of Multivalue

We currently have many types that have to be multivalue capable out of syntax compliance but are never
actually made to be multivalue types. This creates overheads in the server but also in how we code
the valuesets themself.

The multivalue type should be removed. The syntax should imply if the type is single or multivalue.
For example, bool is always single value. utf8 is single value. utf8strings is multivalue.

This allows consistent handling with SCIM which has separate handling of multi/single value types.

### Indexing

Currently we have a number of indexing flags like equality, substring, presence. In the future we
would like to add ordering. However, these don't make sense on all types. How do you "order" certificates?
How do you "substring" an integer? How do you perform equality on two passkeys?

To resolve this schema should indicate a boolean for "indexed" or not based on if the value will be
queried. The syntax will then imply the class of indexes that will be emitted for the type.

### Migration Behaviour

Certain attributes for internal server migrations need to have their content asserted, merged, or
ignored. This behaviour should be flagged in the schema to make it more consistent and visible how
these types will be affected during a migration, and to prevent human error.

### SubAttributes and SubAttribute Syntax

SCIM allows complex structure types to exist. We could consider a schema syntax to allow generic
structures of these based on a set of limited and restricted SubAttributes. For example we might
have a SubAttribute of "Mail" and it allows two SubAttributeValues of "value": email, and "primary": bool.

We would need more thought here about this, and it's likely it's own whole separate topic including
how to handle it with access controls.

