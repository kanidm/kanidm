# Account Policy

Account Policy defines the security requirements that accounts must meet and influences users
sessions.

Policy is defined on groups so that membership of a group influences the security of its members.
This allows you to express that if you can access a system or resource, then the account must also
meet the policy requirements.

## Default Account Policy

By default Account Policy is applied to `idm_all_accounts`. This provides the defaults that
influence all accounts in Kanidm. This policy can be modified the same as any other group's policy.

## Policy Resolution

When an account is affected by multiple policies, the strictest component from each policy is
applied. This can mean that two policies interact and make their combination stricter than their
parts.

| value            | ordering       |
| ---------------- | -------------- |
| auth-session     | smallest value |
| privilege-expiry | smallest value |

### Example Resolution

If we had two policies where the first defined:

```
auth-session: 86400
privilege-expiry: 600
```

And the second

```
auth-session: 3600
privilege-expiry: 3600
```

As the value of auth-session from the second is smaller we would take that. We would take the
smallest value of privilege-expiry from the first. This leaves:

```
auth-session: 3600
privilege-expiry: 600
```

## Enabling Account Policy

Account Policy is enabled on a group with the command:

```
kanidm group account-policy enable <group name>
kanidm group account-policy enable my_admin_group
```

## Setting Maximum Session Time

The auth-session value influences the maximum time in seconds that an authenticated session can
exist for. After this time, the user must reauthenticate.

This value provides a difficult balance - forcing frequent re-authentications can frustrate and
annoy users. However extremely long sessions allow a stolen or disclosed session token/device to
read data for an extended period. Due to Kanidm's read/write separation this mitigates the risk of
disclosed sessions as they can only _read_ data, not write it.

To set the maximum authentication session time

```
kanidm group account-policy auth-expiry <group name> <seconds>
kanidm group account-policy auth-expiry my_admin_group 86400
```

## Setting Maximum Privilege Time

The privilege-expiry time defines how long a session retains it's write privileges after a
reauthentication. After this time, the session returns to read-only mode.

To set the maximum privilege time

```
kanidm group account-policy privilege-expiry <group name> <seconds>
kanidm group account-policy privilege-expiry my_admin_group 900
```
