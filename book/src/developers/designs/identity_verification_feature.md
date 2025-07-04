# The identity verification API

The following diagram describes the api request/response of the identity verification feature (from here on referred as
“idv”). The api takes an _IdentifyUserRequest_ instance as input, which in the diagram is represented by a circle shape,
and it returns an _IdentifyUserResponse_, which is represented by a rectangle. The response rectangles are colored with
green or red, and although all responses belong to the same enum, the colors are meant to provide additional
information. A green response means that the input was valid and therefore it contains the next step in the identity
verification flow, while a red response means the input was invalid and the flow terminates there. Note that the
protocol is completely stateless, so the following diagram is not to be intended as a state machine, for the idv state
machine go [here](#the-identity-verification-state-machine).

![idv api diagram](diagrams/idv_api_diagram.drawio.svg)

Note that the endpoint path is _`/v1/person/:id/_identify_user`_, therefore every request is made up by the
_IdentifyUserRequest_ and an Id. Furthermore to use the api a user needs to be authenticated, so we link their userid to
all their idv requests. Since all requests contains this additional information, there is a subset of responses that
solely depend on it and therefore can **always** be returned regardless of what _IdentifyUserRequest_ what provided.
Below you can find said subset along with an explanation for every response.

![generic api responses](diagrams/idv_generic_responses.drawio.svg)

Here are the _IdentifyUserRequest_ and _IdentifyUserResponse_ enums just described as found inside the
[source code](https://github.com/kanidm/kanidm/blob/05b35df413e017ca44cc4410cc255b63728ef373/proto/src/internal.rs#L32)
:

```rust
pub enum IdentifyUserRequest {
    Start,
    SubmitCode { other_totp: u32 },
    DisplayCode,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum IdentifyUserResponse {
    IdentityVerificationUnavailable,
    IdentityVerificationAvailable,
    ProvideCode { step: u32, totp: u32 },
    WaitForCode,
    Success,
    CodeFailure,
    InvalidUserId,
}
```

## The identity verification state machine

Here is the idv state machine, built on top of the idv endpoint request/response types previously described. Since the
protocol provided by kanidm is completely stateless and doesn’t involve any online communication, some extra work is
needed on the ui side to make things work. Specifically on the diagram you will notice some black arrows: they represent
all the state transitions entirely driven by the ui without requiring any api call. You’ll also notice some empty
rectangles with a red border: they represent the scenario in which the other user tells us that the code provided
doesn’t match. This makes the idv fail, and it’s the only case in which the failure is entirely driven by the ui.

![idv state machine](diagrams/idv_state_machine.drawio.svg)
