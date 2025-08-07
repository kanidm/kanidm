# Sub-Entries

As Kanidm has grown we have encountered issues with growing complexity of values and valuesets. These
can be hard to create and add, they touch a lot of the codebase, and they add complexity to new
features or changes.

These complex valueset types (such as authsession, oauth2session, application passwords) arose out
of a need to have data associated to an account, but that data required structure and nesting
of certain components.

Rather than continue to add more complex and unwieldy valuesets, we need a way to create entries
that refer to others.

## Existing Referential Code

The existing referential integrity code is designed to ensure that values from one entry are removed
cleanly if the referenced entry is deleted. As an example, a group with a member "ellie" should have
the reference deleted when the entry "ellie" is deleted.

If the group were deleted, this has no impact on ellie, since the reference is defining a weak
relationship - the user is a member of a group.

## What Is Required

What we need in a new reference type are the following properties.

* A sub-entry references an owning entry
* A sub-entry is deleted when the owning entry is deleted (aka recycled)
* Sub-entries can not exist without a related owning entry
* Deletion of the sub-entry does not delete the entry
* When an entry is searched, specific types of sub-entries can be fetched at the same time
* The owning entry can imply access controls to related sub-entries
* Conditional creation of sub-entries and adherence to certain rules (such as, "identity X can create sub-entry Y only if the owning entry is itself/X")
* Subentries may have a minimal / flattened representation that can inline to the owning entry via a phantomAttribute

Properties we can not maintain are

* An entry has a `must` relationship for a sub-entry to exist
* SubEntries may not have SubEntries

## Example SubEntry

Auth Sessions, OAuth2 Sessions, ApiTokens, Application Passwords, are examples of candidates to become SubEntries.

```
class: person
name: ellie
uuid: A

class: subentry
class: authsession
SubEntryOf: A
sessionStartTime: ...
sessionEntTime: ...
sessionId: ...
```

Good candidates are structured data that are logically indendent from the owning entry and may not
always need presentation with the owning entry. Displaying a person does not always require it's
subentries to be displayed.

## Non-Examples

Some attributes should not become subentries, generally things with minimal or small structures
that benefit from being present on the owning entry for human consumption.

* Mail
* Address
* Certificates
* Passkeys

## AccessControls

Access Controls need to be able to express a relationship between an owner and the subEntry. For
example we want rules that can express:

* Identity X can create an AuthSession where the AuthSession must reference Identity X
* `idm_admins` can delete/modify ApiTokens where the owning entries are persons and not members of `idm_high_priv`

We need to extend the `filter` type to support a `SubEntryOfSelf`. This
is similar to the `SelfUUID` type, but rather than expanding to `Uuid(...)` it would expand to
`SubEntryOf(...)`. As `create` access controls define that the resultant entry *must* match
the target filter, this achieves the goal.

We also need a new ACP Target Type. This new target type needs two filters - one
to express the relationship to the SubEntry, and the other to the relationship of the SubEntryOwner. This
would constitute two filters

```
SubEntryTarget: class eq apitokens
EntryTarget: person and not memberOf idm_high_priv
```

Both conditions must be met for the access control to apply. In the case of a `create`, the SubEntryTarget
is used for assertion of the SubEntry adherence to the filter. SubEntryTarget implies "class eq SubEntry". EntryTarget
implies `and not class eq SubEntry`.

## Search / Access

How to handle where we need to check the entryTarget if we don't have the entry? Do SubEntries need
to auto-dereference and link to their owning entry for filter application?

If we deref, we need to be careful to avoid ref-count loops, since we would need to embed Arc or Weak
references into the results.


Alternately, is this where we need pre-extraction of access controls?

Could SubEntries only be accessed via their Parent Entry via embedding?



## Deletion

During a deletion, all deleted entries will also imply the deletion of their SubEntries. These SubEntries
will be marked with a flag to distinguish them as an indirect delete.

## Reviving

During a revive, a revived entry implies the revival of it's SubEntries that are marked as indirect
deleted.

## Replication / Consistency

If a SubEntry is created with out an owner, or becomes a orphaned due to a replication conflict of
it's owning entry, the SubEntries are deleted.





