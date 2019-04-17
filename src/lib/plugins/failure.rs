// Failure inducing plugin
//
// Designed for complex server tests, this plugin is able to look at Event
// metadata and induce failures in various stages of query server operation
// execution. The idea is that we should be able to test and assert that
// rollback events do not have negative effects on various server elements.
