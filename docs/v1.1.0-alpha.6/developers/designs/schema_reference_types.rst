
Schema References
-----------------

On top of normal schema, it is sometimes necessary for objects to be able to refer
to each other. The classic example of groups containing members, and memberof which
is a reverse lookup of these relationships. In order to improve the clarity and
performance of these types, instead of having them simply as free-utf8 fields that
require upkeep, we should have a dedicated reference type in the schema.

Benefits
--------

* The reference can be translated from name -> uuid and uuid -> name
during ProtoEntry <-> Entry transformations. This means that renames of objects, don't affect
references, but does mean they continue to render their linkage correctly.
* We can implement native referential integrity for the types rather than relying on admin and
plugin configuration to match the internal types.
* User defined classes will inherit referential behaviour by using
the correct schema attribute types.

Implementation
--------------

Schema needs a type for REFERENCE.

Schema must validate that the attributes content is a UUID.

During ProtoEntry -> Entry, names are translated to UUID,
and UUID are validated.

During ProtoModify -> Modify, names are translated same as ProtoEntry.

During Entry -> ProtoEntry, UUID is transformed to name.

ACP still applies to the attribute as before, it's only that the
content can be transformed between Entry to ProtoEntry.

Reference types must only apply to live objects.

Internally, during modify/create/search, we need to only use the UUID
types because we won't have the transform step (but this is correct
behaviour).

test case
---------

given a new attribute type X with MUST, X has value UUID1 which is from object Y.

Delete object Y, and ensure that it is handled correctly (reject the delete due to schema
violation)

If the attribute X was MAY, then allow the delete, and referential integrity.

Question
--------

When do we check the reference is a valid UUID? We have one chance
at ProtoEntry -> Entry, but we need to still check that internal
changes are valid. Perhaps we do this in schemaValidation? It seems
like a layer violation, but it's the time when we go from EntryInvalid -> EntryValid
so it's also "correct" state wise.
