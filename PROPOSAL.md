# Proposal for a way to store name history

## The implementation
The idea is to make use of the currently existing server plugin system. Currently, transaction entries are ran through a series of plugins that can look at them and perform actions on them.
We can create a new plugin that check a user's name if it is altered, then embed the name in the entry being modified. This will be in the form of a list storing the name and the change id.

## The crab
The Rust implementation will be similar to the existing entries: create a symbolic struct that derives the `Plugin` trait. For the modify function we can perform the actions specified: look for a change in name, then add to a list in the entry.
For what to put in the entry, we can create a struct storing a list of names and change ids, that will derive the `ValueSetT` trait for use as a value in the entry's key-value map.