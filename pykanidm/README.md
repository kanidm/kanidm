# kanidm

A Python module for interacting with Kanidm.

Thoughts:

- should we allow this to store/run multiple sessions? ie - when you auth as a user, the token's stored in the class in `self.sessions[username]` etc?
- asyncio? it's better, but it's more complex and requires consumers to deal with all that