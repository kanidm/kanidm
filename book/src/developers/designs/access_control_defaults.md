# Access Control Defaults

- Do we need some kind of permission atoms to allow certain tasks?

## Use Cases

- User sign-up portal (need service account that can create users and do cred reset)
- Role for service account generation.
- Remote backup - this account should be able to trigger and retrieve a backup
- Groups should be able to be changed by a managing group (managed by)
- IP limits on accounts?

- Users need to not be able to see other users.
  - Means the user can't read member attr, but can see groups + group info.

- Anonymous needs to be able to be blocked more easily.
- Enable disable self-mail write
- Enable disable self-name-change

## To achieve

- IP access limits
- Managed By rules
- Better group specification syntax (not filters)

## Domain Admin

```mermaid
graph LR

DomainAdmin("Domain Admin") --> AccessControlAdmin("Access Control Admin")
DomainAdmin("Domain Admin") --> AccountPolicyAdmin("Account Policy Admin")
DomainAdmin("Domain Admin") --> DomainConfigAdmin("Domain Config Admin")
DomainAdmin("Domain Admin") --> HPGroupAdmin("HP Group Admin")
DomainAdmin("Domain Admin") --> SchemaAdmin("Schema Admin")
DomainAdmin("Domain Admin") --> SyncAccountAdmin("Sync Account Admin")
```

## IDM Admin

```mermaid
graph LR

IdmAdmin("IDM Admin") --> GroupAdmin("Group Admin")
IdmAdmin("IDM Admin") --> PersonAdmin("Person Admin")
IdmAdmin("IDM Admin") --> PersonPIIModify("Person PII Modify")
IdmAdmin("IDM Admin") --> PersonReadNoPII("Person Read No PII")
IdmAdmin("IDM Admin") --> PosixAccountIncludesCredMod("POSIX Account - [Includes Cred Mod]")
IdmAdmin("IDM Admin") --> RadiusAccountModify("Radius Account Modify")
```

## Integration Admin

```mermaid
graph LR

IntegrationAdmin("Integration Admin") --> OAuth2Admin("OAuth2 Admin")
IntegrationAdmin("Integration Admin") --> PosixAccountConsumer("POSIX Account Consumer")
IntegrationAdmin("Integration Admin") --> RadiusServiceAdmin("Radius Service Admin")
```

## Help Desk

```mermaid
graph LR

HelpDesk("Help Desk") --> PersonCredentialModify("Person Credential Modify")
HelpDesk("Help Desk") --> PersonReadNoPII("Person Read No PII")
```

## Account "Self"

```mermaid
graph LR

SelfMailModify("Self Mail Modify") --> |"Modifies"| Self
SelfRead("Self Read") --> |"Read"| Self
SelfModify("Self Modify") --> |"Writes Secrets"| Self
SelfNameModify("Self Name Modify") --> |"Modifies"| Self
```

## Account-Related

Duplicated for Service Accounts, HP persons, HP service Accounts.

```mermaid
graph LR

PersonOnBoard("Person On Board") --> |"Creates"| Persons("Persons")
PersonAdmin("Person Admin") --> |"Creates Deletes"| Persons("Persons")
PersonPIIModify --> |"Reads Modifies"| Persons
PersonPIIModify("Person PII Modify") -.-> |"Member of"| PersonAdmin
PersonCredentialModify("Person Credential Modify") -.-> |"Member of"| PersonAdmin
PersonCredentialModify("Person Credential Modify") -.-> |"Member of"| PersonOnBoard
PersonCredentialModify --> |"Reads Modifies"| Persons
PersonCredentialModify --> |"Reads"| PersonReadNoPII("Person Read No PII")
PersonAdmin --> PersonReadWithPII("Person Read - With PII")
PersonReadWithPII --> PersonReadNoPII
PersonReadNoPII --> |"Reads"| Persons
PosixAccountIncludesCredMod --> |"Extends (Add Posix Account)"| Persons
```

## Domain and Schema

```mermaid
graph LR

DomainConfigAdmin("Domain Configuration Admin") --> |"Modifies Reads"| Domain
DomainConfigAdmin("Domain Configuration Admin") --> |"Modifies Reads"| System
SyncAccountAdmin("Sync Account Admin") --> |"Creates Modifies Deletes"| SyncAccounts("Sync Accounts")
SchemaAdmin("Schema Admin") --> |"Creates Modifies"| Schema("Schema")
AccessControlAdmin("Access Control Admin") --> |"Creates Modifies Deletes"| AccessControls("Access Controls")
```

## High-Priv and Groups

```mermaid
graph LR

GroupAdmin("Group Admin") --> |"Create Modify Delete"| Groups("Groups")
AccountPolicyAdmin("Account Policy Admin") --> |"Modifies Extends"| Groups("Groups")
GroupAdmin --> |"Modify Delete"| HPGroups("HP Groups")
GroupAdmin --> |"Add Members"| HPGroup("HP Group")

HPGroupAdmin("HP Group Admin") --> HPGroup
GroupAdmin -.-> |"Inherits"| HPGroupAdmin
```

## OAuth2 Specific

```mermaid
graph LR

OAuth2Admin("OAuth2 Admin") --> |"Creates Modifies Delegates"| OAuth2RS("OAuth2 RS")
ScopedMember("Scoped Member") --> |"Reads"| OAuth2RS
```

## POSIX-Specific

```mermaid
graph LR

PosixAccountConsumer("POSIX Account Consumer") --> |"Reads Auths"| PosixAccounts("Posix Accounts")
```

## Radius

```mermaid
graph LR

RadiusServiceAdmin("Radius Service Admin") --> |"Adds Members"| RadiusService("Radius Service")
RadiusService --> |"Reads Secrets"| RadiusAccounts("Radius Accounts")
RadiusAccountModify("Radius Account Modify") --> |"Writes Secrets"| RadiusAccounts
```

## Recycle Bin Admin

```mermaid
graph LR

RecycleBinAdmin("Recycle Bin Admin") --> |"Modifies Reads Revives"| RecycledEntries("Recycled Entries")
```
