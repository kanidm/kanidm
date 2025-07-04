# Groups

Groups are a collection of other entities that exist within Kanidm.

## Creating Groups

Members of `idm_group_admins` can create new groups. `idm_admin` by default has these privileges.

```bash
kanidm group create demo_group --name idm_admin
kanidm group add-members demo_group demo_user --name idm_admin
kanidm group list-members demo_group --name idm_admin
```

After addition, you will see a reverse link from our `demo_user` showing that it is now a _member of_ the group
`demo_group`. Kanidm makes all group membership determinations by inspecting an entry's "memberof" attribute.

```bash
kanidm person get demo_user --name idm_admin
```

## Nested Groups

Kanidm supports groups being members of groups, allowing nested groups. These nesting relationships are shown through
the "memberof" attribute on groups and accounts. This allows nested groups to reflect on accounts.

An example can be easily shown with:

```bash
kanidm group create group_1 --name idm_admin
kanidm group create group_2 --name idm_admin
kanidm person create nest_example "Nesting Account Example" --name idm_admin
kanidm group add-members group_1 group_2 --name idm_admin
kanidm group add-members group_2 nest_example --name idm_admin
kanidm person get nest_example --name anonymous
```

This should result in output similar to:

```text
memberof: idm_all_persons@localhost
memberof: idm_all_accounts@localhost
memberof: group_2@localhost
memberof: group_1@localhost
name: nest_example
```

## Delegated Administration

Kanidm supports delegated administration though the "entry managed by" field. This allows specifying a group or user
account that is the "entry manager" of a group. This allows the entry manager to modify the group without the need to
define new access controls.

The `entry_managed_by` attribute of a group may only be modified by members of `idm_access_control_admins`. During entry
creation `idm_group_admins` may set `entry_managed_by`, but may not change it post creation.

```bash
kanidm group create <NAME> [ENTRY_MANAGED_BY]
kanidm group create delegated_access_group demo_group --name idm_admin
kanidm group get delegated_access_group --name idm_admin
```

Now, as our `demo_user` is a member of `demo_group` they have delegated administration of `delegated_access_group`.

```bash
kanidm login --name demo_user

                                note the use of demo_user --\
                                                            v
kanidm group add-members delegated_access_group admin --name demo_user
kanidm group get delegated_access_group --name demo_user
```
