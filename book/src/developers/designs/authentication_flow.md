# User Authentication Flow

This authentication flow is for interactive users. If you're using a
[service account](../../accounts/service_accounts.md), use
[Bearer authentication](../../accounts/service_accounts.html#api-tokens-with-kanidm-httpsrest-api) with the token.

1. Client sends an init request. This can be either:
   1. `AuthStep::Init` which just includes the username, or
   2. `AuthStep::Init2` which can request a "privileged" session
2. The server responds with a list of authentication methods. (`AuthState::Choose(Vec<AuthAllowed>)`)
3. Client requests auth with a method (`AuthStep::Begin(AuthMech)`)
4. Server responds with an acknowledgement (`AuthState::Continue(Vec<AuthAllowed>)`). This is so the challenge can be
   included in the response, for Passkeys or other challenge-response methods.
   - If required, this challenge/response continues in a loop until the requirements are satisfied. For example, TOTP
     and then Password.
5. The result is returned, either:
   - Success, with the User Auth Token as a `String`.
   - Denied, with a reason as a `String`.

```mermaid
sequenceDiagram;
    autonumber
    participant Client
    participant Kanidm
    
    Note over Client: "I'm Ferris and I want to start auth!"
    Client ->> Kanidm: AuthStep::Init(username)
    Note over Kanidm: "You can use the following methods"
    Kanidm ->> Client: AuthState::Choose(Vec<AuthAllowed>)

    loop Authentication Checks
        Note over Client: I want to use this mechanism
        Client->>Kanidm: AuthStep::Begin(AuthMech)
        Note over Kanidm: Ok, you can do that.
        Kanidm->>Client: AuthState::Continue(Vec<AuthAllowed>)
        Note over Client: Here is my credential
        Client->>Kanidm: AuthStep::Cred(AuthCredential)
        Note over Kanidm: Kanidm validates the Credential,<br /> and if more methods are required,<br /> return them.
        Kanidm->>Client: AuthState::Continue(Vec<AuthAllowed>)
        Note over Client, Kanidm: If there's no more credentials required, break the loop.

    end

    Note over Client,Kanidm: If Successful, return the auth token
    Kanidm->>Client: AuthState::Success(String Token)

    Note over Client,Kanidm: If Failed, return that and a message why.
    Kanidm-xClient: AuthState::Denied(String Token)
```
