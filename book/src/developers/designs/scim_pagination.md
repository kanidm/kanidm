# SCIM Pagination

SCIM Pagination is important for Kanidm to limit the size of responses to clients, and to allow efficient UI's to exist
that show results over multiple pages for large datasets (such as users)

The default pagination in the [SCIM rfc](https://www.rfc-editor.org/rfc/rfc7644#section-3.4.2.4) has many limitations in
how we arrange the items, indexes and other details. The important limitation of this is related to access controls.

[SCIM cursor based pagination](https://datatracker.ietf.org/doc/draft-ietf-scim-cursor-pagination/) is an alternative,
but also has some issues that may prevent us being able to use it.

To satisfy our requirements, we should implement virtual list views.

## SCIM RFC Pagination Limitations

The major limitation of the SCIM RFC pagination is related to _access controls_.

Say that we have 100 users. Our request is only allowed to access a subset of these users, and should only be able to
see a total of 50 users.

When Kanidm queries our backend we get a candidate set that matches the filter, but to apply the access controls we
actually need to fully load the entry in question and determine if it is or is not part of this result set.

So this then raises a problem - how do we actually do this _effeciently_?. Since the RFC pagination only works based on
startIndex relative to the final access control applied result set, when we go to the next page, we don't know as a
server where to position the results to start. We may need to skip the first 5 entries due to access control, then
another 10 which we can see, to position the cursor at index 10, before we can start to access the remaining entries. As
we go further through the pages we would effectively need to check the access of the whole set in the end, just to
access only a few entries at the end of the set.

## SCIM Cursor Based Pagination

Cursor Based Pagination works by adding a nextCursor and previousCursor value to any results that are returned. This
allows us to indicate the offset into the candidate result set, even without access controls being applied.

Lets say that our candidate set has the same 100 entries as before. We skip the first 5, and the next 10 are returned.
We then store the value 16 into the nextCurser. On the next request, Kanidm can skip the first 15 entries then start to
apply access controls again from the 16th entry in the candidate set. This way we delay the scanning until that point.
When we return the next results, we can list the previous page as previousCursor 0 (and the first 15 entries will be
checked again), and the nextCursor at offset 28 (supposing we return 10 entries and skipped 2).

Important here in this scheme is that the next and previous cursor values must be encrypted. This is because we don't
want an external user to be able to determine how many entries they _can't_ see. In some cases this could be used to
determine the value of some attributes by repeatedly querying and bisecting to determine that something must exist
between two values.

This scheme also is good for security as we don't encode anything in the cursor that would allow a replay attack. If the
user was to "go back" to the first page, and a new entry was added that now is valid within the first page, it would be
rendered (and the nextCursor would show the now bumped entry). But were the person to replay a cursor that pointed later
into the list, it won't reveal any new entries, all it can do is cause a number of entries to be skipped.

The major limitation of this approach is you can't arbitrarily offset to a specific page of results. Where you can with
the RFC Pagination, since the number of results is known ahead of time, in this method you only know that there are more
pages, until they run out. For example, if someone wanted to skip to page 5, with 10 results per page, we would need to
effectively scan and apply access controls of the first 40 entries to generate the correct cursor values for the
request. While possible,

Another issue/limitation is how we would calculate the number of totalResults. To calculate totalResults implies we
applied access controls to all the affected entries, leaving us back at the start of this problem.

## Virtual List Views / Pre Authentication

Since security is the primary blocker to the former two implementations, the answer is to precompile the lists that the
user can see. This way only users which are allowed to access the virtual list view are able to make the request, and we
already know they have access to the attributes in question for the list view. These list views also satisfy another
requirement - sorting.

This also then removes the need for cursors since with a precompiled list, we can directly offset to any location in the
list, since we already know that any value in that list is allowed to be accessed by the user.

To maintain the ordering of these lists, each named list view would have a b+tree of values where the keys are inserted
and sorted. After an update is completed, the b+tree (which is optimised for sorting) would be extracted to a vector
(optimised for offset/scanning).

This will require a new index type (sorting), a new access / vlv definition type that contains the query that can be
used for listing.

In the case that a user makes a request where they don't have access to the list view _or_ they are making a query that
does NOT have a list view associated, then the current search process will be taken with a simple sort / result
truncate. Since we have an enforced set of limits on database results then in many cases, this limit window will be hit
unless the result set is small. This way on small searches we will be able to page, but on large requests it will be
denied due to limits.

This also works well with our UiHint framework, where access to the VLV grants access to the listing pages for various
types.
