## User Settings Display Web UI

We need a usable centralized location for users to view and manage their own user settings. User settings do not envelop
credentials, these have their own flow as they are also used in user setup.

- Writing new values requires a writable session -> we will make the user reauthenticate to obtain a temporary
  profile-update-token when they want to update their user settings.
- The UI must display and make editable the following categories:
  - user attributes
  - user ssh public-keys
- The UI must display:
  - user credential status as per [credential-display.rst](credential-display.rst)
  - user groups

### User attributes

These consist of:

- username
- displayname
- legal name
- email address

Future attributes we intend to add:

- profile picture
- zoneinfo/timezone
- locale/preferred language
- address
- phone number

#### Displaying attributes

Attributes should be displayed with

- their descriptive name with tooltips or links if the name may be confusing to non IT people.
- their current value OR if not set: some clear indication that the attribute is not set.
- A method to edit the attribute if it is editable

#### Editing attributes

Users must be able to edit attributes individually. Users should be able to see their changes before saving them. E.g.
via a popup that shows the old vs new value asking to confirm.

#### TODO: Personal Identifiable Information attributes (currently we don't have these attributes)

Certain information should not be displayed in the UI without reauthentication:

- addresses
- phone numbers
- personal emails
- birthdate

### SSH public keys

Ssh public key entries in Kanidm consist of a:

- label : practically the ID of the key in kanidm
- value : the public key

A user may want to change their laptop ssh key by updating the value while keeping the label the same. // TODO: Should a
user be allowed to relabel their kanidm ssh keys ?

#### Displaying ssh keys

Due to their long length they should be line-wrapped into a text field so the entirety is visible when shown. To reduce
visible clutter and inconsistent spacing we will put the values into collapsible elements.

These collapsed elements must include:

- label
- value's key type (ECDSA, rsa, etc..) and may include:
- value's comment, truncated to some max length

#### Editing keys

When editing keys users must be able to add keys, remove keys and update individual key values. Each action will be
committed immediately, thus proper prompts and icons indicating this must be shown (like a floppy disk save icon ?)

### Credential status

Described in [credential-display.rst](credential-display.rst) Must inform the user of the credential update/reset page,
since it is very related and might be what they were looking for instead.

### User groups

Mostly a technical piece of info, should not be in direct view to avoid confusing users. Could be displayed in tree
form.

### User profile HTML Structure

To keep things organised each category will be their own page with a subnavigation bar to navigate between them. Since
htmx cannot (without extensions) swap new scripts into the <head> on swap during boosted navigation, we must do
non-boosted navigation to our profile page OR enable some htmx extension library.

The same htmx limitation means that all JS for every profile categories must be loaded on all profile categories.
Because want to use htmx to swap out content on form submission or page navigation to represent the new state as this is
more efficient than triggering the client to do a redirect.

Every category will get their own Askama template which requires the relevant fields described for each category above.
And example would be

```html
<!-- /profile_templates/ssh_keys_partial.html -->

<!-- TODO: Depending on how we model modifiability of ssh keys this may change -->

(% for ssh_key in ssh_keys %)
<!-- Display ssh_key properties with respect to this doc -->
(% if ssh_key_is_modifiable %)
<!-- more clicky buttons to enable modification/deletion -->
(% endif %) (% endfor %) (% if ssh_key_is_modifiable %)
<!-- Add ssh_key button -->
(% endif %)
```

```js
// ../static/profile.js -->

// Magically gets called on page load and swaps
function onProfileSshKeysSwapped() {
  // Do implementation things like attaching event listeners
}

window.onload = function () {
  // Event triggered by HTMX because we supply a HxTrigger response header when loading this profile category.
  document.body.addEventListener("profileSshKeysSwapped", () => {
    onProfileSshKeysSwapped();
  });
};
```

```rust
#[derive(Template,WebTemplate)]
#[template(path = "profile_templates/ssh_keys_partial.html")]
struct SshKeysPartialView {
    ssh_keys: Vec<SCIMSshKey>, // TODO: Use correct type
    modifiable_state: SshKeysModifiabilityThing // ?
}

fn view_ssh_keys(...) {
    // ...

    let ssh_keys_swapped_trigger = HxResponseTrigger::after_swap([HxEvent::from(KanidmHxEventName::ProfileSshKeysSwapped)]);
    Ok((
        ssh_keys_swapped_trigger,
        HxPushUrl("/ui/profile/ssh_keys".to_string()),
        HtmlTemplate(SshKeysPartialView { ssh_keys,  })
    ).into_response())
}
```
