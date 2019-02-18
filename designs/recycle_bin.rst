
Recycle Bin
-----------

When an entry is deleted, we should move it to a "hidden" state, rather than deleting it. This
allows "undo" of delete operations, by "revival" of the deleted objects.

This is a valuable feature for usability of the system, allowing people to recover from
bad scenarios.

It should also be possible for admins to "recover" from this scenario (likely a unique access
control in itself) where they can send a "revival" request to restore from the recyclebin.

Considerations
--------------

An important consideration is the eventual addition of the name uniqueness constraint. This would
require that deleted objects are not consider in the uniqueness, and revival of an object would
be checked for violation of the uniqueness. Due to the nature of revival (modify) and that it would
take the pre-plugin path this is already easily handled. The complexity is in representation of
filters for internal searches.

We need to default to wrapping all terms in "And(AndNot(class, deleted), <Filter>)".

An option is to scan the filter for and Eq(class, deleted) terms, and if present remove the wrapping
and operation.

A possibly better option is that filter constructors should have two constructors. One that
adds the wrapping AndNot term, and one that does not. This way the plugin implementor only
needs to construct from the correct call, and they would exclude / include recycled items. This
also would allow externally supplied filters to be correctly wrapped. The main consideration here
is that it would require another api endpoint allowing recycle-bin searches. This is probably not
super nice, but I don't want a boolean flag in a searchRequest for "include recycled" as people will
likely make mistakes with it.

However, this makes the admin task of searching for/displaying recycle bin objects harder, because
it would use a different search interface. It also means we would have more end points/access controls
potentially. This is an argument for the filter-scan method, that checks if any component requests
the class, deleted, and if it does, we do not wrap with the AndNot term.


The best solution is a whole seperate interface (/search/recycle/) that has it's own access controls
that is used. By default searches don't look at recycled items (but internal do). This interface would
remove that limitation, but would require access controls to prevent read/changes.

Another example is that we would need a /modify/revive interface solely for revival operations (
which are actually specialised modifies)


