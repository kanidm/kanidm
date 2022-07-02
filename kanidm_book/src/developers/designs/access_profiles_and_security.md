
Access Profiles
===============

Access Profiles (ACPs) are a way of expressing the set of actions which accounts are 
permitted to perform on database records (`object`) in the system.

As a result, there are specific requirements to what these can control and how they are
expressed.

Access profiles define an action of `allow` or `deny`: `deny` has priority over `allow` 
and will override even if applicable. They should only be created by system access profiles
because certain changes must be denied.

Access profiles are stored as entries and are dynamically loaded into a structure that is
more efficent for use at runtime. `Schema` and its transactions are a similar implementation.

Search Requirements
-------------------

A search access profile must be able to limit:

1. the content of a search request and its scope.
2. the set of data returned from the objects visible.

An example:

> Alice should only be able to search for objects where the class is `person` 
> and the object is a memberOf the group called "visible". 
> 
> Alice should only be able to see those the attribute `displayName` for those 
> users (not their `legalName`), and their public `email`.

Worded a bit differently. You need permission over the scope of entries, you need to be able
to read the attribute to filter on it, and you need to be able to read the attribute to recieve
it in the result entry.

If Alice searches for `(&(name=william)(secretdata=x))`, we should not allow this to
proceed because Alice doesn't have the rights to read secret data, so they should not be allowed
to filter on it. How does this work with two overlapping ACPs? For example: one that allows read
of name and description to class = group, and one that allows name to user. We don't want to
say `(&(name=x)(description=foo))` and it to be allowed, because we don't know the target class
of the filter. Do we "unmatch" all users because they have no access to the filter components? (Could
be done by inverting and putting in an AndNot of the non-matchable overlaps). Or do we just
filter our description from the users returned (But that implies they DID match, which is a disclosure).

More concrete:

```yaml
search {
    action: allow
    targetscope: Eq("class", "group")
    targetattr: name
    targetattr: description
}

search {
    action: allow
    targetscope: Eq("class", "user")
    targetattr: name
}

SearchRequest {
    ...
    filter: And: {
        Pres("name"),
        Pres("description"),
    }
}
```

A potential defense is:

```yaml
acp class group: Pres(name) and Pres(desc) both in target attr, allow
acp class user: Pres(name) allow, Pres(desc) deny. Invert and Append
```

So the filter now is:

```yaml
And: {
    AndNot: {
        Eq("class", "user")
    },
    And: {
        Pres("name"),
        Pres("description"),
    },
}
```

This would now only allow access to the `name` and `description` of the class `group`.

If we extend this to a third, this would work. A more complex example:

```yaml
search {
    action: allow
    targetscope: Eq("class", "group")
    targetattr: name
    targetattr: description
}

search {
    action: allow
    targetscope: Eq("class", "user")
    targetattr: name
}

search {
    action: allow
    targetscope: And(Eq("class", "user"), Eq("name", "william"))
    targetattr: description
}
```

Now we have a single user where we can read `description`. So the compiled filter above as:

```yaml
And: {
    AndNot: {
        Eq("class", "user")
    },
    And: {
        Pres("name"),
        Pres("description"),
    },
}
```

This would now be invalid, first, because we would see that `class=user` and `william` has no name
so that would be excluded also. We also may not even have "class=user" in the second ACP, so we can't
use subset filter matching to merge the two.

As a result, I think the only possible valid solution is to perform the initial filter, then determine
on the candidates if we *could* have have valid access to filter on all required attributes. IE
this means even with an index look up, we still are required to perform some filter application
on the candidates.

I think this will mean on a possible candidate, we have to apply all ACP, then create a union of
the resulting targetattrs, and then compared that set into the set of attributes in the filter.

This will be slow on large candidate sets (potentially), but could be sped up with parallelism, caching
or other methods. However, in the same step, we can also apply the step of extracting only the allowed
read target attrs, so this is a valuable exercise.

Delete Requirements
-------------------

A `delete` profile must contain the `content` and `scope` of a delete.

An example:

> Alice should only be able to delete objects where the `memberOf` is
> `purgeable`, and where they are not marked as `protected`.

Create Requirements
-------------------

A `create` profile defines the following limits to what objects can be created, through the combination of filters and atttributes.

An example: 

> Alice should only be able to create objects where the `class` is `group`, and can
> only name the group, but they cannot add members to the group.

An example of a content requirement could be something like "the value of an attribute must pass a regular expression filter". 
This could limit a user to creating a group of any name, except where the group's name contains "admin". 
This a contrived example which is also possible with filtering, but more complex requirements are possible.

For example, we want to be able to limit the classes that someone *could* create on an object
because classes often are used in security rules.

Modify Requirements
-------------------

A `modify` profile defines the following limits:

- a filter for which objects can be modified,
- a set of attributes which can be modified.

A `modify` profile defines a limit on the `modlist` actions. 

For example: you may only be allowed to ensure `presence` of a value. (Modify allowing purge, not-present, and presence).

Content requirements (see [Create Requirements](#create-requirements)) are out of scope at the moment.

An example:

> Alice should only be able to modify a user's password if that user is a member of the
> students group.

**Note:** `modify` does not imply `read` of the attribute. Care should be taken that we don't disclose
the current value in any error messages if the operation fails.

Targeting Requirements
-----------------------

The `target` of an access profile should be a filter defining the objects that this applies to.

The filter limit for the profiles of what they are acting on requires a single special operation
which is the concept of "targeting self". 

For example: we could define a rule that says "members of group X are allowed self-write to the `mobilePhoneNumber` attribute".

An extension to the filter code could allow an extra filter enum of `self`, that would allow this
to operate correctly, and would consume the entry in the event as the target of "Self". This would
be best implemented as a compilation of `self -> eq(uuid, self.uuid)`.

Implementation Details
----------------------

CHANGE: Receiver should be a group, and should be single value/multivalue? Can *only* be a group.

Example profiles:

```yaml
search {
    action: allow
    receiver: Eq("memberof", "admins")
    targetscope: Pres("class")
    targetattr: legalName
    targetattr: displayName
    description: Allow admins to read all users names
}

search {
    action: allow
    receiver: Self
    targetscope: Self
    targetattr: homeAddress
    description: Allow everyone to read only their own homeAddress
}

delete {
    action: allow
    receiver: Or(Eq("memberof", "admins), Eq("memberof", "servicedesk"))
    targetscope: Eq("memberof", "tempaccount")
    description: Allow admins or servicedesk to delete any member of "temp accounts".
}

// This difference in targetscope behaviour could be justification to change the keyword here
// to prevent confusion.
create {
    action: allow
    receiver: Eq("name", "alice")
    targetscope: And(Eq("class", "person"), Eq("location", "AU"))
    createattr: location
    createattr: legalName
    createattr: mail
    createclass: person
    createclass: object
    description: Allow alice to make new persons, only with class person+object, and only set
        the attributes mail, location and legalName. The created object must conform to targetscope
}

modify {
    action: allow
    receiver: Eq("name", "claire")
    targetscope: And(Eq("class", "group"), Eq("name", "admins"))
    presentattr: member
    description: Allow claire to promote people as members of the admins group.
}

modify {
    action: allow
    receiver: Eq("name", "claire")
    targetscope: And(Eq("class", "person"), Eq("memberof", "students"))
    presentattr: sshkeys
    presentattr: class
    targetclass: unixuser
    description: Allow claire to modify persons in the students group, and to grant them the
        class of unixuser (only this class can be granted!). Subsequently, she may then give
        the sshkeys values as a modification.
}

modify {
    action: allow
    receiver: Eq("name", "alice")
    targetscope: Eq("memberof", "students")
    removedattr: sshkeys
    description: Allow allice to purge or remove sshkeys from members of the students group,
        but not add new ones
}

modify {
    action: allow
    receiver: Eq("name", "alice")
    targetscope: Eq("memberof", "students")
    removedattr: sshkeys
    presentattr: sshkeys
    description: Allow alice full control over the ssh keys attribute on members of students.
}

// This may not be valid: Perhaps if <*>attr: is on modify/create, then targetclass, must
// must be set, else class is considered empty.
//
// This profile could in fact be an invalid example, because presentattr: class, but not
// targetclass, so nothing could be granted.
modify {
    action: allow
    receiver: Eq("name", "alice")
    targetscope: Eq("memberof", "students")
    presentattr: class
    description: Allow alice to grant any class to members of students.
}
```

Formalised Schema
-----------------

A complete schema would be:

### Attributes

| Name                   | Single/Multi | Type              | Description           |
| ---                    | ---          | ---               |                       |
| acp_allow              | single value | bool              |                       |
| acp_enable             | single value | bool              | This ACP is enabled   |
| acp_receiver           | single value | filter            |  ??? |
| acp_targetscope        | single value | filter            |  ??? |
| acp_search_attr        | multi value  | utf8 case insense | A list of attributes that can be searched. |
| acp_create_class       | multi value  | utf8 case insense | Object classes in which an object can be created.  | 
| acp_create_attr        | multi value  | utf8 case insense | Attribute Entries that can be created.  | 
| acp_modify_removedattr | multi value  | utf8 case insense | Modify if removed?                      |
| acp_modify_presentattr | multi value  | utf8 case insense | ??? |
| acp_modify_class       | multi value  | utf8 case insense | ??? |

### Classes

| Name                   | Must Have                         |  May Have                  |
|         ---            |               ---                 |          ---               |
| access_control_profile | `[acp_receiver, acp_targetscope]` | `[description, acp_allow]` |
| access_control_search  | `[acp_search_attr]`               |                            |
| access_control_delete  |                                   |                            |
| access_control_modify  |                                   | `[acp_modify_removedattr, acp_modify_presentattr, acp_modify_class]` |
| access_control_create  |                                   | `[acp_create_class, acp_create_attr]` |

**Important**: empty sets really mean empty sets! 

The ACP code will assert that both `access_control_profile` *and* one of the `search/delete/modify/create` 
classes exists on an ACP. An important factor of this design is now the ability to *compose* 
multiple ACP's into a single entry allowing a `create/delete/modify` to exist! However, each one must 
still list their respective actions to allow proper granularity.

"Search" Application
------------------

The set of access controls is checked, and the set where receiver matches the current identified
user is collected. These then are added to the users requested search as:

```
And(<User Search Request>, Or(<Set of Search Profile Filters))
```

In this manner, the search security is easily applied, as if the targets to conform to one of the
required search profile filters, the outer `And` condition is nullified and no results returned.

Once complete, in the translation of the entry -> proto_entry, each access control and its allowed
set of attrs has to be checked to determine what of that entry can be displayed. Consider there are
three entries, A, B, C. An ACI that allows read of "name" on A, B exists, and a read of "mail" on
B, C. The correct behaviour is then:

```
A: name
B: name, mail
C: mail
```

So this means that the `entry -> proto entry` part is likely the most expensive part of the access
control operation, but also one of the most important. It may be possible to compile to some kind
of faster method, but initially a simple version is needed.

"Delete" Application
------------------

Delete is similar to search, however there is the risk that the user may say something like:

```
Pres("class").
```

Were we to approach this like search, this would then have "every thing the identified user
is allowed to delete, is deleted". A consideration here is that `Pres("class")` would delete "all"
objects in the directory, but with the access control present, it would limit the deletion to the
set of allowed deletes.

In a sense this is a correct behaviour - they were allowed to delete everything they asked to
delete. However, in another it's not valid: the request was broad and they were not allowed access
to delete everything they requested.

The possible abuse vector here is that an attacker could then use delete requests to enumerate the 
existence of entries in the database that they do not have access to. This requires someone to have 
the delete privilege which in itself is very high level of access, so this risk may be minimal.

So the choices are:

 1. Treat it like search and allow the user to delete what they are allowed to delete, 
   but ignore other objects
 2. Deny the request because their delete was too broad, and they must specify a valid deletion request.

Option #2 seems more correct because the `delete` request is an explicit request, not a request where
you want partial results. Imagine someone wants to delete users A and B at the same time, but only
has access to A. They want this request to fail so they KNOW B was not deleted, rather than it
succeed and have B still exist with a partial delete status.

However, a possible issue is that Option #2 means that a delete request of
`And(Eq(attr, allowed_attribute), Eq(attr, denied))`,  which is rejected may indicate presence of the 
`denied` attribute. So option #1 may help in preventing a security risk of information disclosure.

<!-- TODO
@yaleman: not always, it could indicate that the attribute doesn't exist so it's an invalid filter, but
    that would depend if the response was "invalid" in both cases, or "invalid" / "refused"
-->

This is also a concern for modification, where the modification attempt may or may not
fail depending on the entries and if you can/can't see them.

**IDEA:** You can only `delete`/`modify` within the read scope you have. If you can't
read it (based on the read rules of `search`), you can't `delete` it. This is in addition to the filter
rules of the `delete` applying as well. So performing a `delete` of `Pres(class)`, will only delete
in your `read` scope and will never disclose if you are denied access.


<!-- TODO
@yaleman: This goes back to the commentary on Option #2 and feels icky like SQL's `DELETE FROM <table>` just deleting everything. It's more complex from the client - you have to search for a set of things to delete - then delete them.
Explicitly listing the objects you want to delete feels.... way less bad. This applies to modifies too.  😁
-->

"Create" Application
------------------

Create seems like the easiest to apply. Ensure that only the attributes in `createattr` are in the
`createevent`, ensure the classes only contain the set in `createclass`, then finally apply
`filter_no_index` to the entry to entry. If all of this passes, the create is allowed.

A key point is that there is no union of `create` ACI's - the WHOLE ACI must pass, not parts of
multiple. This means if a control say "allows creating group with member" and "allows creating
user with name", creating a group with `name` is not allowed - despite your ability to create
an entry with `name`, its classes don't match. This way, the administrator of the service can define
create controls with specific intent for how they will be used without the risk of two
controls causing unintended effects (`users` that are also `groups`, or allowing invalid values.

An important consideration is how to handle overlapping ACI. If two ACI *could* match the create
should we enforce both conditions are upheld? Or only a single upheld ACI allows the create?

In some cases it may not be possible to satisfy both, and that would block creates. The intent
of the access profile is that "something like this CAN" be created, so I believe that provided
only a single control passes, the create should be allowed.

"Modify" Application
------------------

Modify is similar to Create, however we specifically filter on the `modlist` action of `present`,
`removed` or `purged` with the action. The rules of create still apply; provided all requirements
of the modify are permitted, then it is allowed once at least one profile allows the change.

A key difference is that if the modify ACP lists multiple `presentattr` types, the modify request 
is valid if it is only modifying one attribute. IE we say `presentattr: name, email`, but we
only attempt to modify `email`.

Considerations
--------------

* When should access controls be applied? During an operation, we only validate schema after
  pre* Plugin application, so likely it has to be "at that point", to ensure schema-based 
  validity of the entries that are allowed to be changed.
* Self filter keyword should compile to `eq("uuid",  "....")`. When do we do this and how?
* `memberof` could take `name` or `uuid`, we need to be able to resolve this correctly, but this is 
  likely an issue in `memberof` which needs to be addressed, ie `memberof uuid` vs `memberof attr`.
* Content controls in `create` and `modify` will be important to get right to avoid the security issues
  of LDAP access controls. Given that `class` has special importance, it's only right to give it extra
  consideration in these controls.
* In the future when `recyclebin` is added, a `re-animation` access profile should be created allowing
  revival of entries given certain conditions of the entry we are attempting to revive. A service-desk user
  should not be able to revive a deleted high-privilege user.
