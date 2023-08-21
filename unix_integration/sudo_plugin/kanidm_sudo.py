"""

This is a sudo plugin for Kanidm, it allows you to use
Kanidm as a source of truth for sudoers.

See Sudo's documentation for how to use this plugin: https://www.sudo.ws/posts/2020/05/sudo-1.9-using-the-group-plugin-from-python/

*** untested in a live environment, someone please test this ***

Example running it on the CLI:

```shell
KANIDM_CONFIG=~/.config/kanidm kanidm_sudo.py \
        username@example.org krab_admins
INFO:root:Checking if username@example.org is a member of krab_admins
INFO:root:result: 1
```

- @yaleman

"""
import asyncio
import os
import sys
from typing import Any, Dict

import kanidm

if __name__ != "__main__":
    import sudo  # type: ignore
else:
    import logging

    class sudo(object):  # type: ignore
        class Plugin(object):
            pass

        # https://github.com/sudo-project/sudo/blob/1b9fb405a3c02944ff9afbde03114ac4772b022f/plugins/python/example_group_plugin.py#L16
        class RC:
            ACCEPT = 1
            OK = 1
            REJECT = 0
            ERROR = -1
            USAGE_ERROR = -2


class SudoGroupPlugin(sudo.Plugin):  # type: ignore
    def __init__(self, **kwargs: Dict[str, Any]):
        """initialize the plugin"""
        super().__init__(**kwargs)
        try:
            self.event_loop = asyncio.new_event_loop()

            self.kanidm_client = kanidm.KanidmClient(
                config_file=os.getenv("KANIDM_CONFIG", "/etc/kanidm/kanidm.toml"),
            )
            self.auth_as_anonymous()
        except Exception as error:
            logging.error(error)

    def query(self, user: str, group_name: str, **kwargs: Any) -> int:
        """do the query thing"""
        try:
            groups = self.event_loop.run_until_complete(self.kanidm_client.get_groups())

            for group in groups:
                logging.debug("Group: %s", group.name)
                if group.name == group_name:
                    if group.has_member(user):
                        return sudo.RC.ACCEPT  # type: ignore
        except Exception as error:
            logging.error("Failed to check if %s is in %s: %s", user, group_name, error)
            return sudo.RC.ERROR  # type: ignore
        return sudo.RC.REJECT  # type: ignore
        # print(f"looking for group {group}")
        # raise NotImplementedError("Sorry!")
        # group_has_user = user in hardcoded_user_groups.get(group, [])
        # return sudo.RC.ACCEPT if group_has_user else sudo.RC.REJECT

    def auth_as_anonymous(self) -> None:
        """authenticate as anonymous"""
        self.event_loop.run_until_complete(self.kanidm_client.auth_as_anonymous())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <group>")
        sys.exit(1)

    if os.getenv("DEBUG"):
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    username = sys.argv[1]
    group = sys.argv[2]
    logging.info("Checking if %s is a member of %s", username, group)
    plugin = SudoGroupPlugin()
    res = plugin.query(username, group)
    logging.info("result: %s", res)
    sys.exit(res * -1)
