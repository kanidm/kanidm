""" kanidmradius CLI """

import sys

from . import _get_radius_token

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} username")
    print(sys.argv)
else:
    token = _get_radius_token(sys.argv[1])
    print(f"{token=}")
    print(f"groups: {token['groups']}")
