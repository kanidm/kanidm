""" tests types """

from kanidm.types import AuthInitResponse


def test_auth_init_response() -> None:
    """tests AuthInitResponse"""
    testobj = {
        "sessionid": "crabzrool",
        "state": {
            "choose": ["passwordmfa"],
        },
    }

    testval = AuthInitResponse.parse_obj(testobj)
    assert testval.sessionid == "crabzrool"
