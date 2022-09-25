""" Testing JWT things """

from datetime import datetime, timezone

import pytest

from kanidm.tokens import JWS, TokenStore

# pylint: disable=line-too-long
TEST_TOKEN = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im1KQTgtTURfeFRxQXBmSU9nbFptNXJ6RWhoQ3hDdjRxZFNpeGxjV1Q3ZmsiLCJ5IjoiNy0yVkNuY0h3NEF1WVJpYVpYT2FoVXRGMUE2SDd3eUxrUW1FekduS0pKcyIsImFsZyI6IkVTMjU2IiwidXNlIjoic2lnIn0sInR5cCI6IkpXVCJ9.eyJzZXNzaW9uX2lkIjoiZjExOTg2NzMtNGI5MC00NjE4LWJkZTctMTBiY2M2YzhjOGE0IiwiYXV0aF90eXBlIjoiZ2VuZXJhdGVkcGFzc3dvcmQiLCJleHBpcnkiOlsyMDIyLDI2NSwyODM2Niw4MDI1MjUwMDBdLCJ1dWlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDE4IiwibmFtZSI6ImlkbV9hZG1pbiIsImRpc3BsYXluYW1lIjoiSURNIEFkbWluaXN0cmF0b3IiLCJzcG4iOiJpZG1fYWRtaW5AbG9jYWxob3N0IiwibWFpbF9wcmltYXJ5IjpudWxsLCJsaW1fdWlkeCI6ZmFsc2UsImxpbV9ybWF4IjoxMjgsImxpbV9wbWF4IjoyNTYsImxpbV9mbWF4IjozMn0.cln3gRV3NdgbGqYeD26mBSHFGOaFXak2UA5umvj_Xw30dMS8ECTnJU7lvLyepRTW_VzqUJHbRatPkQ1TEuK99Q"


def test_jws_parser() -> None:
    """ tests the parsing """


    expected_header = {
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "mJA8-MD_xTqApfIOglZm5rzEhhCxCv4qdSixlcWT7fk",
            "y": "7-2VCncHw4AuYRiaZXOahUtF1A6H7wyLkQmEzGnKJJs",
            "alg": "ES256",
            "use": "sig"
        },
        "typ": "JWT"
    }

    expected_payload = {
        "session_id": "f1198673-4b90-4618-bde7-10bcc6c8c8a4",
        "auth_type": "generatedpassword",
        "expiry": [
            2022,
            265,
            28366,
            802525000
        ],
        "uuid": "00000000-0000-0000-0000-000000000018",
        "name": "idm_admin",
        "displayname": "IDM Administrator",
        "spn": "idm_admin@localhost",
        "mail_primary": None,
        "lim_uidx": False,
        "lim_rmax": 128,
        "lim_pmax": 256,
        "lim_fmax": 32
    }

    test_jws = JWS(TEST_TOKEN)

    assert test_jws.header.dict() == expected_header
    assert test_jws.payload.dict() == expected_payload

def test_tokenstuff() -> None:
    """ tests stuff """
    token_store = TokenStore()
    token_store["idm_admin"] = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im1KQTgtTURfeFRxQXBmSU9nbFptNXJ6RWhoQ3hDdjRxZFNpeGxjV1Q3ZmsiLCJ5IjoiNy0yVkNuY0h3NEF1WVJpYVpYT2FoVXRGMUE2SDd3eUxrUW1FekduS0pKcyIsImFsZyI6IkVTMjU2IiwidXNlIjoic2lnIn0sInR5cCI6IkpXVCJ9.eyJzZXNzaW9uX2lkIjoiMTBmZDJjYzMtM2UxZS00MjM1LTk4NjEtNWQyNjQ3NTAyMmVkIiwiYXV0aF90eXBlIjoiZ2VuZXJhdGVkcGFzc3dvcmQiLCJleHBpcnkiOlsyMDIyLDI2NSwzMzkyMywyOTQyNTQwMDBdLCJ1dWlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDE4IiwibmFtZSI6ImlkbV9hZG1pbiIsImRpc3BsYXluYW1lIjoiSURNIEFkbWluaXN0cmF0b3IiLCJzcG4iOiJpZG1fYWRtaW5AbG9jYWxob3N0IiwibWFpbF9wcmltYXJ5IjpudWxsLCJsaW1fdWlkeCI6ZmFsc2UsImxpbV9ybWF4IjoxMjgsImxpbV9wbWF4IjoyNTYsImxpbV9mbWF4IjozMn0.rq1y7YNS9iCBWMmAu-FSa4-o4jrSSnMO_18zafgvLRtZFlB7j-Q68CzxceNN9C_1EWnc9uf4fOyeaSNUwGyaIQ"

    info = token_store.token_info('idm_admin')
    print(f"Parsed token: {info}")
    if info is None:
        pytest.skip()
    print(info.expiry_datetime)
    assert datetime(year=2022, month=9, day=22, hour=9, minute=25, second=23, tzinfo=timezone.utc) == info.expiry_datetime
