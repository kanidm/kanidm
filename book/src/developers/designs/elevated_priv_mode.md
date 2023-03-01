# Elevation of Privilege Inside User Sessions

To improve user experience, we need to allow long lived sessions in browsers. This is especially
important as a single sign on system, users tend to be associated 1 to 1 with devices, and by having
longer lived sessions, they have a smoother experience.

However, we also don't want user sessions to have unbound write permissions for the entire (possibly
unlimited) duration of their session.

Prior art for this is github, which has unbounded sessions on machines and requests a
re-authentication when a modifying or sensitive action is to occur.

For us to implement this will require some changes to how we manage sessions.

## Session Issuance

- ISSUE: Sessions are issued identically for service-accounts and persons
- CHANGE: service-accounts require a hard/short session expiry limit and always have elevated
  permissions
- CHANGE: persons require no session expiry and must request elevation for privs.

- ISSUE: Sessions currently indicate all read-write types as the same access scope type.
- CHANGE: Split sessions to show rwalways, rwcapable, rwactive

- ISSUE: Sessions currently are recorded identically between service-accounts, persons, and api
  tokens
- CHANGE: Change the session storage types to have unique session types for these ✅

- ISSUE: Access Scope types are confused by api session using the same types.
- CHANGE: Use access scope only as the end result of current effective permission calculation and
  not as a method to convert to anything else. ✅

  AccessScope { ReadOnly, ReadWrite, Synchronise }

  // Bound by token expiry ApiTokenScope { ReadOnly, ReadWrite, Synchronise }

  UatTokenScope { ReadOnly, // Want to avoid "read write" here to prevent dev confusion.
  PrivilegeCapable, PrivilegeActive { expiry }, ReadWrite, }

  SessionScope { Ro, RwAlways, PrivCapable, }

  ApiTokenScope { RO RW Sync }

  AuthSession if service account rw always, bound expiry

      if person
        priv cap, unbound exp
           - Should we have a "trust the machine flag" to limit exp though?
           - can we do other types of cryptographic session binding?

## Session Validation

- CHANGE: Session with PrivCapable indicates that re-auth can be performed.
- CHANGE: Improve how Uat/Api Token scopes become Access Scopes
- CHANGE: Remove all AccessScope into other types. ✅

## Session Re-Authentication

- Must be performed by the same credential that issued the session originally
  - This is now stored in the session metadata itself.
  - Does it need to be in the cred-id?

- CHANGE: Store the cred id in UAT so that a replica can process the operation in a replication sync
  failure?
  - This would rely on re-writing the session.
- CHANGE: Should we record in the session when priv-escalations are performed?

## Misc

- CHANGE: Compact/shrink UAT size if possible.

## Diagram

                                                                                                        Set                                               
                                                                             ┌───────────────────────PrivActive────────────────────┐                      
                                                                             │                         + Exp                       │                      
                                                                             │                                                     │                      
                                  ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐        │                      .───────────.         ┌────────────────┐              
                                                                             │   ┌────────────────▶( If Priv Cap )───────▶│Re-Auth-Allowed │              
                                  │                                 │        │   │                  `───────────'         └────────────────┘              
                                       DB Content                    ┌ ─ ─ ─ ┼ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─                                                        
    ┌───────────────────┐         │                                 │    JWT │   │                │                                                       
    │                   │                                            │       ▼   │                                                                        
    │    AuthSession    │         │         ┌──────────────┐        │    ┌──────────────┐         │                                                       
    │                   │                   │SessionScope  │         │   │UatScope      │                                                                 
    │  Service Account  │         │         │- RO          │        │    │- RO          │         │                                                       
    │     -> RWAlways   │──────────────────▶│- RW          │─────────┼──▶│- RW          │──────────────────────────┐                                      
    │                   │         │         │- PrivCapable │        │    │- PrivCapable │         │                │                                      
    │      Person       │                   └──────────────┘         │   │- PrivActive  │                          │                                      
    │     -> PrivCap    │         │                                 │    └──────────────┘         │                │                                      
    │                   │                                            │                                             │                                      
    └───────────────────┘         │                                 │                             │                ▼                                      
                                                                     │                                     ┌──────────────┐                               
                                  │                                 │                             │        │AccessScope   │              ┌───────────────┐
                                                                     │                                     │- RO          │              │               │
                                  │                                 │                             │        │- RW          │───────────▶  │Access Controls│
                                                                     │                                     │- Sync        │              │               │
     ┌───────────────────┐        │       ┌─────────────────┐       │     ┌──────────────┐        │        └──────────────┘              └───────────────┘
     │                   │                │ApiSessionScope  │        │    │ApiTokenScope │                         ▲                                      
     │ Create API Token  │        │       │- RO             │       │     │- RO          │        │                │                                      
     │                   │───────────────▶│- RW             │────────┼───▶│- RW          │─────────────────────────┘                                      
     │Access Based On Req│        │       │- Sync           │       │     │- Sync        │        │                                                       
     │                   │                └─────────────────┘        │    │              │                                                                
     └───────────────────┘        │                                 │     └──────────────┘        │                                                       
                                                                     │                                                                                    
                                  │                                 │                             │                                                       
                                   ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─

## TODO:

1. Remove the ident-only access scope, it's useless! ✅
1. Split tokens to have a dedicated session type separate to uat sessions. ✅
1. Change uat session access scope recording to match service-account vs person intent.
1. Change UAT session issuance to have the uat purpose reflect the readwrite or readwrite-capable
   nature of the session, based on _auth-type_ that was used.
1. Based on auth-type, limit or unlimit expiry to match the intent of the session.
