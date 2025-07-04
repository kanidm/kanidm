# Custom Claim Maps

Some OAuth2 services may consume custom claims from an id token for access control or other policy decisions. Each
custom claim is a key:values set, where there can be many values associated to a claim name. Different applications may
expect these values to be formatted (joined) in different ways.

Claim values are mapped based on membership to groups. When an account is a member of multiple groups that would receive
the same claim, the values of these maps are merged.

To create or update a claim map on a client:

```shell
kanidm system oauth2 update-claim-map <name> <claim_name> <kanidm_group_name> [values]...
kanidm system oauth2 update-claim-map nextcloud account_role nextcloud_admins admin login ...
```

To change the join strategy for a claim name. Valid strategies are csv (comma separated value), ssv (space separated
value) and array (a native json array). The default strategy is array.

```shell
kanidm system oauth2 update-claim-map-join <name> <claim_name> [csv|ssv|array]
kanidm system oauth2 update-claim-map-join nextcloud account_role csv
```

Example claim formats:

```text
# csv
claim: "value_a,value_b"

# ssv
claim: "value_a value_b"

# array
claim: ["value_a", "value_b"]
```

To delete a group from a claim map

```shell
kanidm system oauth2 delete-claim-map <name> <claim_name> <kanidm_group_name>
kanidm system oauth2 delete-claim-map nextcloud account_role nextcloud_admins
```
