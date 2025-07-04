# OAuth2 Device Flow

The general idea is that there's two flows.

## Device/Backend

- Start an auth flow
- Prompt the user with the link
- On an interval, check the status
  - Still pending? Wait.
  - Otherwise, handle the result.

## User

- Go to the "check user code" page
- Ensure user is authenticated
- Confirm that the user's happy for this auth session to happen
  - This last step is the usual OAuth2 permissions/scope prompt

```mermaid
flowchart TD
    DeviceStatus -->|Pending| DeviceStatus
    D[Device] -->|Start Backend flow| BackendFlowStart(Prompt User with details)
    BackendFlowStart -->|User Clicks Link| DeviceGet
    BackendFlowStart -->|Check Status| DeviceStatus
    DeviceStatus -->|Result - error or success| End


    DeviceGet -->|Not Logged in, Valid Token| LoginFlow(Login Flow)
    DeviceGet -->|Invalid Token, Reprompt| DeviceGet
    LoginFlow --> DeviceGet
    DeviceGet -->|Logged in, Valid Token| ConfirmAccess(User Prompted to authorize)
    ConfirmAccess -->|Confirmed| End(Done!)
```
