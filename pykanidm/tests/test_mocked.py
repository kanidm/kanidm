""" mocked tests """

# import asyncio
# import aiohttp
# import pytest

# import pook
# from kanidm import KanidmClient
# from kanidm.exceptions import AuthMechUnknown


# this kinda half sorta works but not really - you have to be able to mock a second call and I'm not sure how yet.
# example of how to do the thing https://github.com/h2non/pook/issues/73

# @pytest.mark.mocked
# @pytest.mark.asyncio
# async def test_authenticate_password_raises_authmechunknown() -> None:
#     """tests the authenticate() flow"""

#     client_config = KanidmClient(uri="https://localhost:8443")

#     with pytest.raises(AuthMechUnknown):
#         async with aiohttp.ClientSession() as session:
#             with pook.post('https://localhost:8443/v1/auth',
#                         reply=200, response_type='json',response_json={
#                             "sessionid": "12345",
#                             "state": {
#                                 "choose" : ["password"],
#                                 "continue" : ["12345"],
#                                 "success" : True,
#                                 }
#                         },
#                         response_headers={"x-kanidm-auth-session-id" : "12345"}
#             ):
#                 # async with session.request("GET", "https://localhost:8443") as resp:

#                     # assert resp.status == 404
#                 auth_result = await client_config.authenticate_password(username="testing", password="asdfasdfsdf")
#                 print(f"{auth_result=}")
