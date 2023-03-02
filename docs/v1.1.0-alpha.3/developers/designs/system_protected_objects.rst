System Protected Objects
------------------------

There are a number of system provided objects and functions that are important
for correct operation of the server. It's important we protect these from certain
types of modifications so that the system has a baseline of correct functionality.

Some of this is protected by the migrations system built into the server, which
will correct and "set" certain items to a known state on startup. However, like
all IDM systems, downtime/restarts are rare, so we have to account for human
error and provide constraints to maintain a healthy running system.

What needs protecting?
----------------------

The current list (july 2019) is:

* Core schema (enough to make attributetypes/classtypes/memberof/acp operate)
* Anonymous
* Admin
* systeminfo

Additionally, the scope of protection is limited - or rather, the scope of what is
allowed.

* New system protected items can only be created via internal operations, preventing
accidental creation of these.
* schema classtypes can have must/may altered on classes
* schema attributetypes can have index altered on classes
* anonymous can be locked
* admin can be locked, and password changed (or other credentials changed).

The plugin design
-----------------

This should be a plugin, as the hooks exist in the correct places to intercept and block
the required operations, saving custom coding. The plugin will:

* Block any create on "class": "system".
* Block any delete on "class": "system".
* Block modify to "class": "system" where the affect attr is NOT in the allowed mod set.

The modify block will not be class aware, because schema protects us from other odd behaviours.
An example - addition of account lock to a schema element. This would be "allowed" by this plugin
because account lock will be in the allowed set for system, but schema would not allow addition
of accountlock to a schema element thus protecting us. Because class will NEVER be in the
allowed set for a system protected type, we can trust that these bounds won't be exceeded.

Why not ACP?
------------

It was considered to provide default ACP's that would protect system items. This was rejected because:

* it would require a "deny" acp type, and I do not wish to create this, as people could then create their own deny rules (always incorrect!)
* There would be a lot of acp's involved in this protection (but acp's are expressive enough to provide it!)
* The acp's would need a self-referencing acp to protect themselves from modification.
* Having a separate plugin to protect this will be faster than acp processing because we check less filters (But this is not a strong argument)
* the plugin can provide targeted error messages about why they were denied, rather than a generic acp denied message.
* the plugin can provide detailed testing of edge cases in a confined manner

