# Oauth2 Refresh Tokens

Due to how Kanidm authentication sessions were originally implemented they had short session times
(1 hour) due to the lack of privilege separation in tokens. Now with privilege separation being
implemented session lengths have been extended to 8 hours with possible increases in the future.

However, this leaves us with an issue with oauth2 - oauth2 access tokens are considered valid until
their expiry and we should not issue tokens with a validity of 8 hours or longer since that would
allow rogue users to have a long window of usage of the token before they were forced to re-auth. It
also means that in the case that an account must be forcefully terminated then the user would retain
access to applications for up to 8 hours or more.

To prevent this, we need oauth2 tokens to "check in" periodically to re-afirm their session
validity.

This is performed with access tokens and refresh tokens. The access token has a short lifespan
(proposed 15 minutes) and must be refreshed with Kanidm which can check the true session validity
and if the session has been revoked. This creates a short window for revocation to propagate to
oauth2 applications since each oauth2 application must periodically check in to keep their access
token alive.

## Risks

Refresh tokens are presented to the relying server where they receive an access token and an
optional new refresh token. Because of this, it could be possible to present a refresh token
multiple times to proliferate extra refresh and access tokens away from the system. Preventing this
is important to limit where the tokens are used and monitor and revoke them effectively.

In addition, old refresh tokens should not be able to be used once exchanged, they should be "at
most once". If this is not enforced then old refresh tokens can be used to gain access to sessions
even if the associated access token was expired by many hours and it's refresh token was already
used.

This is supported by
[draft oauth security topics section 2.2.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.2.2)
and
[draft oauth security topics refresh token protection](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#refresh_token_protection)

Refresh tokens must only be used by the client application associated. Kanidm strictly enforces this
already with our client authorisation checks. This is discussed in
[rfc6749 section 10.4](https://www.rfc-editor.org/rfc/rfc6749#section-10.4).

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
     │ IAT 1 │                   │ IAT 2 │─────6. Refresh──────────┘               │ IAT 3 │           
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

## Attack Detection

[draft oauth security topics section 4.14.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.14.2)
specifically calls out that when refresh token re-use is detected then all tokens of the session
should be canceled to cause a new authorisation code flow to be initiated.

## Inactive Refresh Tokens

Similar
[draft oauth security topics section 4.14.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.14.2)
also discusses that inactive tokens should be invalidated after a period of time. From the view of
the refresh token this is performed by an internal exp field in the encrypted refresh token.

From the servers side we will require a "not after" parameter that is updated on token activity.
This will also require inactive session cleanup in the server which can be extended into the session
consistency plugin that already exists.

Since the act of refreshing a token is implied activity then we do not require other signaling
mechanisms.

# Questions

Currently with authorisation code grants and sessions we issue these where the sessions are recorded
in an async manner. For consistency I believe the same should be true here but is there a concern
with the refresh being issued but a slight delay before it's recorded? I think given the nature of
our future replication we already have to consider the async/eventual nature of things, so this
doesn't impact that further, and may just cause client latency in the update process.

However, we also don't want a situation where our async/delayed action queues become too full or
overworked. Maybe queue monitoring/backlog issues are a separate problem though.
