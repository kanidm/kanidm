
Access Profiles
---------------

Access profiles are a way of expressing which persons are allowed what actions to be
performed on any database record (object) in the system.

As a result, there are specific requirements to what these can control and how they are
expressed.

Access profiles define an action of allow or deny: Denies are enforced before allows, and
will override even if applicable. They should only be created by system access profiles,
because we have certain requirements to deny certain changes.

Access profiles are stored as entries and are dynamically loaded into a structure that is
more efficent for use at runtime. Schema and it's transactions are a similar implementation.

Search Requirements
-------------------

A search access profile, must be able to limit the content of a search request and it's
scoping.

A search access profile, must be able to limit the returned set of data from the objects
visible.

An example is that user Alice should only be able to search for objects where the class
is person, and where they are a memberOf "visible" group. Alice should only be able to
see those users displayNames (not their legalName for example), and their public email.

Worded a bit differently. You need permission over the scope of entries, you need to be able
to read the attribute to filter on it, and you need to be able to read the attribute to recieve
it in the result entry.

Threat: If we search for '(&(name=william)(secretdata=x))', we should not allow this to
proceed because you don't have the rights to read secret data, so you should not be allowed
to filter on it. How does this work with two overlapping ACPs? For example one that allows read
of name and description to class = group, and one that allows name to user. We don't want to
say '(&(name=x)(description=foo))' and have it allowed, because we don't know the target class
of the filter. Do we "unmatch" all users because they have no access to the filter components? (Could
be done by inverting and putting in an AndNot of the non-matchable overlaps). Or do we just
filter our description from the users returned (But that implies they DID match, which is a disclosure).

More concrete:

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

A potential defense is:

    acp class group: Pres(name) and Pres(desc) both in target attr, allow
    acp class user: Pres(name) allow, Pres(desc) deny. Invert and Append

    So the filter now is:
    And: {
        AndNot: {
            Eq("class", "user")
        },
        And: {
            Pres("name"),
            Pres("description"),
        },
    }

    This would now only allow access to the name/desc of group.

If we extend this to a third, this would work. But a more complex example:

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

Now we have a single user where we can read desc. So the compiled filter above as:

    And: {
        AndNot: {
            Eq("class", "user")
        },
        And: {
            Pres("name"),
            Pres("description"),
        },
    }

This would now be invalid, first, because we would see that class=user and william has no name
so that would be excluded also. We also may not even have "class=user" in the second ACP, so we can't
use subset filter matching to merge the two.

As a result, I think the only possible valid solution is to perform the initial filter, then determine
on the candidates if we *could* have have valid access to filter on all required attributes. IE
this means even with an index look up, we still are required to perform some filter application
on the candidates.

I think this will mean on a possible candidate, we have to apply all ACP, then create a union of
the resulting targetattrs, and then compared that set into the set of attributes in the filter.

This will be slow on large candidate sets (potentially), but could be sped up with parallelism, caching
or other. However, in the same step, we can also apply the step of extracting only the allowed
read target attrs, so this is a valuable exercise.

Delete Requirements
-------------------

A delete profile must contain the content and scope of a delete.

An example is that user Alice should only be able to delete objects where the memberOf is
"purgeable", and where they are not marked as "protected".

Create Requirements
-------------------

A create profile defines a filtering limit on what content can be created and it's requirements.

A create profile defines a limit on what attributes can be created in addition to the filtering
requirements.

An example is user Alice should only be able to create objects where the class is group, and can
only name the group - they can not add members to the group.

A content requriemnt could be something such as the value an attribute can contain must conform to a
regex, IE, you can create a group of any name, except where the name contains "admin" somewhere
in it's name. Arguable, this is partially possible with filtering.

For example, we want to be able to limit the classes that someone *could* create on something
because classes often are used as a security type.


Modify Requirements
-------------------

A modify profile defines a filter limit of what can be modified in the directory.

A modify profile defines a limit of what attributes can be altered in the modification.

A modify profile defines a limit on the modlist actions: For example you may only be allowed to
ensure presence of a value. (Modify allowing purge, not-present, and presence).

Content requirements (see create requirements) are out of scope at the moment.

An example is Alice should only be able to modify a users password if that user is a member of the
students group.

Note, modify, does not imply *read* of the attribute. Care should be taken that we don't disclose
the current value in any error messages if the operation fails.


Targetting Requirements
-----------------------

The target of an access profile should be a filter defining the objects that this applies to.

THe filter limit for the profiles of what they are acting on requires a single special operation
which is the concept of "targetting self". For example, we could define a rule that says "members
of group X are allowed self-write mobile phone number".

An extension to the filter code, could allow an extra filter enum of "Self", that would allow this
to operate correctly, and would consume the entry in the event as the target of "Self". This would
be best implemented as a compilation of self -> eq(uuid, self.uuid).


Implementation Details
----------------------

CHANGE: Receiver should be a group, and should be single value/multivalue? Can *only* be a group.

Example profiles:

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
        createscope: And(Eq("class", "person"), Eq("location", "AU"))
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
        purgedattr: sshkeys
        description: Allow allice to purge sshkeys from members of the students group.
    }

    modify {
        action: allow
        receiver: Eq("name", "alice")
        targetscope: Eq("memberof", "students")
        purgedattr: sshkeys
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


Search Application
------------------

The set of access controls is checked, and the set where receiver matches the current identified
user is collected. These then are added to the users requested search as:

    And(<User Search Request>, Or(<Set of Search Profile Filters))

In this manner, the search security is easily applied, as if the targets to conform to one of the
required search profile filters, the outer And condition is nullified and no results returned.

Once complete, in the translation of the entry -> proto_entry, each access control and it's allowed
set of attrs has to be checked to determine what of that entry can be displayed. Consider there are
three entries, A, B, C. An ACI that allows read of "name" on A, B exists, and a read of "mail" on
B, C. The correct behaviour is then:

    A: name
    B: name, mail
    C: mail

So this means that the entry -> proto entry part is likely the most expensive part of the access
control operation, but also one of the most important. It may be possible to compile to some kind
of faster method, but initially a simple version is needed.

Delete Application
------------------

Delete is similar to search, however there is the risk that the user may say something like:

    Pres("class").

Now, were we to approach this like search, this would then have "every thing the identified user
is allowed to delete, is deleted". A consideration here is that Pres("class") would delete "all"
objects in the directory, but with the access control present, it would limit the delete to the
set of allowed deletes.

In a sense, this is a correct behaviour - they were allowed to delete everything they asked to
delete. However, in another it's not valid: the request was broad and they were not allowed access
to delete everything they request.

The possible abuse here is that you could then use deletes to determine existance of entries in
the database that you do not have access to. This however, requires someone to HAVE a delete
privilege which is itself, very high level of access, so this risk may be minimal.

So the choices are:

    * Treat it like search and allow the user to delete "what they are allowed to delete"
    * Deny the request, because their delete was too broad, and they should specify better
       what they want to delet.

Option 2 seems more correct because the delete request is an explicit request, not a request where
you want partial results - imagine someone wants to delete users A, B at the same time, but only
have access to A. They wwant this request to fail so they KNOW B was not deleted, rather than
succeed and have B still exist with a partial delete status.

Create Application
------------------

Create seems like the easiest to apply. Ensure that only the attributes in createattr are in the
createevent, ensure the classes only contain the set in createclass, then finally apply
filter_no_index to the entry to entry. If all of this passes, the create is allowed.

A key point, is that there is no union of create aci's - the WHOLE aci must pass, not parts of
multiple.

An important consideration is how to handle overlapping aci. If two aci *could* match the create
should we enforce both conditions are upheld? Or only a single upheld aci allows the create?

In some cases it may not be possible to satisfy both, and that would block creates. The intent
of the access profile is that "something like this CAN" be created, so I believe that provided
only a single control passes, the create should be allowed.

Modify Application
------------------

Modify is similar to above, however, we specifically filter on the modlist action of present,
removed or purged with the action. Otherwise, the rules of create stand where provided all requirements
of the modify are "upheld", then it is allowed provided at least a single profile allows the change.

A key difference is that if the modify lists multiple presentattr types, the modify so long as it has
one presentattr of the profile, it is conforming. IE we say "presentattr: name, email", but we
only attempt to modify "email".

Considerations
--------------

* When should access controls be applied? During an operation, we only schema validate after
  pre plugins, so likely it has to be "at that point", to ensure schema validity of the entries
  we want to assert changes to.
* Self filter keyword should compile to eq("uuid",  "...."). When do we do this and how?
* memberof could take name or uuid, we need to be able to resolve this correctly, but this is likely
  a memberof issue we need to address, ie memberofuuid vs memberof attr.
* Content controls in create and modify will be important to get right to avoid the security issues
  of ldap access controls. Given that class has special importance, it's only right to give it extra
  consideration in these controls.
* In the future when recyclebin is added, a re-animation access profile should be created allowing
  revival of entries given certain conditions of the entry we are attempting to revive.


