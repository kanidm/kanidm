# Oauth2 Refresh Tokens

Due to how Kanidm authentication sessions were originally implemented they had short session times
(1 hour) due to the lack of privilege separation in tokens. Now with privilege separation being
implemented session lengths have been extended to 8 hours with possible increases in the future.

However, this leaves us with an issue with oauth2 - oauth2 access tokens are considered valid until
their expiry and we should not issue tokens with a validity of 8 hours or longer since that would
allow rogue users to have a long window of usage of the token before they were forced to re-auth.

To prevent this, we need oauth2 tokens to "check in" periodically to re-afirm their session
validity.

This is performed with access tokens and refresh tokens. The access token has a short lifespan (15
minutes) and must be refreshed with Kanidm which can check the true session validity and if the
session has been revoked. This creates a short window for revocation to propagate to oauth2
applications.

## Risks

Refresh tokens are presented to the oauth2 server where they receive an access token and an optional
new refresh token. Because of this, it could be possible to present a refresh token multiple times
to proliferate extra refresh and access tokens away from the system. Preventing this is important to
limit where the tokens are used.

In addition, old refresh tokens should not be able to be used once exchanged, they should be "at
most once". If this is not enforced then old refresh tokens can be used to gain access to sessions
even if the associated access token was expired by many hours and it's refresh token was already
used.

## Design

          ┌─────────────────────────────────────────┐
          │Kanidm                                   │
          │                                         │
          │ ┌─────────┐                ┌─────────┐  │
          │ │         │                │         │  │
          │ │         │                │         │  │
          │ │ Session │  3. Update     │ Session │  │
          │ │  NIB 1  │─────NIB───────▶│  NIB 2  │  │
          │ │         │                │         │  │
          │ │         │                │         │  │
          │ │         │                │         │  │
          │ └─────────┘                └─────────┘  │
          │   │                           │         │
          └───┼───────────────────────────┼─────────┘
         ┌────┘             ▲        ┌────┘          
         │                  │        │               
         │                  │        │               
    1. Issued               │   4. Issued            
         │                  │        │               
         │                  │        │               
         │                  │        │               
         ▼                  │        ▼               
     ┌───────┐              │    ┌───────┐           
     │       │              │    │       │           
     │Access │              │    │Access │           
     │   +   │              │    │   +   │           
     │Refresh│──2. Refresh──┘    │Refresh│           
     │ IAT 1 │                   │ IAT 2 │           
     │       │                   │       │           
     └───────┘                   └───────┘

In this design we associate a "not issued before" (NIB) timestamp to our sessions. For a refresh
token to be valid for issuance, the refresh tokens IAT must be greater than or equal to the NIB.

In this example were the refresh token with IAT 1 re-used after the second token was issued, then
this condition would fail as the NIB has advanced to 2. Since IAT 1 is not greater or equal to NIB 2
then the refresh token _must_ have previously been used for access token exchange.

In a replicated environment this system is also stable and correct even if a session update is
missed.

                                              2.                                                       
                  ┌───────────────────────Replicate────────────────┐                                   
                  │                                                │                                   
                  │                                                │                                   
          ┌───────┼─────────────────────────────────┐       ┌──────┼──────────────────────────────────┐
          │Kanidm │                                 │       │Kanidm│                                  │
          │       │                                 │       │      ▼                                  │
          │ ┌─────────┐                ┌─────────┐  │       │ ┌─────────┐                 ┌─────────┐ │
          │ │         │                │         │  │       │ │         │                 │         │ │
          │ │         │                │         │  │       │ │         │                 │         │ │
          │ │ Session │  4. Update     │ Session │  │       │ │ Session │   7. Update     │ Session │ │
          │ │  NIB 1  │─────NIB───────▶│  NIB 2  │  │       │ │  NIB 1  │ ─────NIB───────▶│  NIB 3  │ │
          │ │         │                │         │  │       │ │         │                 │         │ │
          │ │         │                │         │  │       │ │         │                 │         │ │
          │ │         │                │         │  │       │ │         │                 │         │ │
          │ └─────────┘                └─────────┘  │       │ └─────────┘                 └─────────┘ │
          │   │                           │         │       │      ▲                        │         │
          └───┼───────────────────────────┼─────────┘       └──────┼────────────────────────┼─────────┘
         ┌────┘             ▲        ┌────┘                        │                   ┌────┘          
         │                  │        │                             │                   │               
         │                  │        │                             │                   │               
    1. Issued               │   5. Issued                          │              8. Issued            
         │                  │        │                             │                   │               
         │                  │        │                             │                   │               
         │                  │        │                             │                   │               
         ▼                  │        ▼                             │                   ▼               
     ┌───────┐              │    ┌───────┐                         │               ┌───────┐           
     │       │              │    │       │                         │               │       │           
     │Access │              │    │Access │                         │               │Access │           
     │   +   │              │    │   +   │                         │               │   +   │           
     │Refresh│──3. Refresh──┘    │Refresh│                         │               │Refresh│           
     │ IAT 1 │                   │ IAT 2 │─────6. Refresh──────────┘               │ IAT 1 │           
     │       │                   │       │                                         │       │           
     └───────┘                   └───────┘                                         └───────┘

In this example, we can see that the replication of the session with NIB 1 happens to the second
Kanidm server, but the replication of session with NIB 2 has not occurred yet. If the token that was
later issued with IAT 2 was presented to the second server it would still be valid and able to
refresh since IAT 2 is greater or equal to NIB 1. This would also prompt the session to advance to
NIB 3 such that when replication begun again, the session with NIB 3 would take precedence over the
former NIB 2 session.

While this allows a short window where a former access token could be used on the second replica,
this infrastructure being behind load balancers and outside of an attackers influence significantly
hinders the ability to attack this for very little gain.
