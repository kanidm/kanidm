
MemberOf
--------

Member Of is a plugin that serves a fundamental tradeoff: precomputation of
the relationships between a group and a user is more effective than looking
up those relationships repeatedly.

There are a few reasons for this to exist.

The major one is that the question is generally framed "what groups is this person
a member of". This is true in terms of application access checks (is user in group Y?), nss' calls
ie 'id name'. As a result, we want to have our data for our user and groups in a close locality.
Given the design of the KaniDM system, where we generally frame and present user id tokens, it
is upon the user that we want to keep the reference to it's groups.

Now at this point one could consider "Why not just store the groups on the user in the first place?".
There is a security benefit to the relationship of "groups have members" rather than "users are
members of groups". That benefit is delegated administration. It is much easier to define access
controls over "who" can alter the content of a group, including the addition of new members, where
the ability to control writing to all users memberOf attribute would mean that anyone with that right
could add anyone, to any group.

IE, if Claire has the write access to "library users" she can only add members to that group.

However, if users took memberships, for claire to add "library users", we would need to either allow
claire to arbitrarily write any group name to users, OR we would need to increase the complexity
of the ACI system to support validation of the content of changes.


So as a result - from a user interaction viewpoint, management of groups that have members is the
simpler, and more powerful solution, however from a query and access viewpoint, the relation ship
of what group is a user member of is the more useful structure.

To this end, we have the member of plugin. Given a set of groups and there members, update the reverse
reference on the users to contain the member of relationship to the group.


There is one final benefit to memberOf - it allows us to have *fast* group nesting capability
where the inverse look up becomes N operations to resolve the full structure.

Design
------

Due to the nature of this plugin, there is a single attribute - 'member' - whos content is examined
to build the relationship to others - 'memberOf'. We will examine a single group and user situation
without nesting. We assume the user already exists, as the situation where the group exists and we add
the user can't occur due to refint.

* Base Case

The basecase is the state where memberOf:G-uuid is present in U:memberOf. When this case is met, no
action is taken. To determine this, we assert that entry pre:memberOf == entry post:memberOf in
the modification - IE no action was taken.

* Modify Case.

as memberOf:G-uuid is not present in U:memberOf, we do a "modify" to add it. The modify will recurse
to the basecase, that asserts, it is present then will return.


Now let's consider the nested case. G1 -> G2 -> U. We'll assume that G2 -> U already exists
but that now we need to add G1 -> G2. This is now trivial to apply given that we use recursion
to apply these changes.

An important aspect of this is that groups *also* contain memberOf attributes: This benefits us because
we can then apply the memberOf from our group to the members of the group!

::

    G1              G2              U
    member: G2      member: U
                    memberOf: G1    memberOf: G1, G2

So at each step, if we are a group, we take our uuid, and add it to the set, and then make a present
modification of our memberOf + our uuid. So translated:

::


    G1              G2              U
    member: G2      member: U
    memberOf: -     memberOf: -     memberOf: G2

    -> [ G1, ]

    G1              G2              U
    member: G2      member: U
    memberOf: -     memberOf: G1    memberOf: G2

                    -> [ G2, G1 ]

    G1              G2              U
    member: G2      member: U
    memberOf: -     memberOf: G1    memberOf: G2, G1

It's important to note, we only recures on Groups - nothing else. This is what breaks the
cycle on U, as memberOf is now fully applied.


As a result of our base-case, we can now handle the most evil of cases: circular nested groups
and cycle breaking.

::

    G1              G2              G3
    member: G2      member: G3      member: G1
    memberOf: --    memberOf: --    memberOf: --

    -> [ G1, ]

    G1              G2              G3
    member: G2      member: G3      member: G1
    memberOf: --    memberOf: G1    memberOf: --

                    -> [ G2, G1 ]

    G1              G2              G3
    member: G2      member: G3      member: G1
    memberOf: --    memberOf: G1    memberOf: G1-2

                                    -> [ G3, G2, G1 ]

    G1              G2              G3
    member: G2      member: G3      member: G1
    memberOf: G1-3  memberOf: G1    memberOf: G1-2

    -> [ G3, G2, G1 ]

    G1              G2              G3
    member: G2      member: G3      member: G1
    memberOf: G1-3  memberOf: G1-3  memberOf: G1-2

                    -> [ G3, G2, G1 ]

    G1              G2              G3
    member: G2      member: G3      member: G1
    memberOf: G1-3  memberOf: G1-2  memberOf: G1-3

                                    -> [ G3, G2, G1 ]

    G1              G2              G3
    member: G2      member: G3      member: G1
    memberOf: G1-3  memberOf: G1-2  memberOf: G1-3

    BASE CASE -> Application of G1-3 on G1 has no change. END.

To supplement this, *removal* of a member from a group is the same process - but instead we
use the "removed" modify keyword instead of present. The base case remains the same: if no
changes occur, we have completed the operation.


Considerations
--------------

* Preventing recursion: As of course, we are using a recursive algo, it has to end. The base case
is "is there no groups with differences" which causes us to NO-OP and return.

* Replication; Because each server has MO, then content of the member of should be consistent. However
what should be considered is the changelog items to ensure that the member changes are accurately
reflected inside of the members.

* Fixup: Simply apply a modify of "purged: *memberof*", and that should cause
recalculation. (testing needed).

