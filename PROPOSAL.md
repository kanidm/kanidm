# Proposal for a way to store name history
## Summary
This proposal includes a solution for Issue [#345](https://github.com/kanidm/kanidm/issues/345) of this project, the high level implementation details, related tasks and potential further development.

## The implementation
The idea is to make use of the currently existing server plugin system. Currently, transaction entries are ran through a series of plugins that can look at them and perform actions on them.
We can create a new plugin that check a user's name if it is altered, then embed the name in the entry being modified. This will be in the form of a list storing the name and the change id.

## The crab
The Rust implementation will be similar to the existing entries: create a symbolic struct that derives the `Plugin` trait. For the modify function we can perform the actions specified: look for a change in name, then add to a list in the entry.
For what to put in the entry, we can create a struct storing a list of names and change ids, that will derive the `ValueSetT` trait for use as a value in the entry's key-value map.

## Additional tasks
Along with implementing name history, testing is also needed to make sure it works correctly:
- The new Plugin module will also include unit tests, testing the Plugin functions implemented for the struct.
- Integration tests might also be added to check if if the new Plugin works well with existing ones.

## Further developments
After this project is finished, there are some further work that can be done regarding this specific feature:
- Implement a config feature that allows admins to set how many times a user can change their name. This might be achieved by storing more info in the Entry and add additional checks in our new PLugin.
- A "name claim" system might be implemented to allow users to claim specific names.

There are also other work I would like to participate in Kanidm during the GSOC period, mostly part of the Access Control rework since some of the issues here have been open for a long time:
- [#116](https://github.com/kanidm/kanidm/issues/116): Make auditing of what-was-read clearer.
- [#611](https://github.com/kanidm/kanidm/issues/611): IP access controls for anonymous.
- [#117](https://github.com/kanidm/kanidm/issues/117): Add REST api/action for showing ACP eval.