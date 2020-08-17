import sys
import requests
import logging
import os
import json

MAJOR, MINOR, _, _, _ = sys.version_info

if MAJOR >= 3:
    import configparser
    # Absolutely fuck you python3
    from functools import reduce
else:
    import ConfigParser as configparser

# Setup the config too
print(os.getcwd())

CONFIG = configparser.ConfigParser()
CONFIG.read('/data/config.ini')

GROUPS = [
    {
        "name": x.split('.')[1],
        "vlan": CONFIG.get(x, "vlan")
    }
    for x in CONFIG.sections()
    if x.startswith('group.')
]

REQ_GROUP = CONFIG.get("radiusd", "required_group")
if CONFIG.getboolean("kanidm_client", "strict"):
    CA = CONFIG.get("kanidm_client", "ca", fallback=True)
else:
    CA = False
USER = CONFIG.get("kanidm_client", "user")
SECRET = CONFIG.get("kanidm_client", "secret")
DEFAULT_VLAN = CONFIG.get("radiusd", "vlan")
TIMEOUT = 8

URL = CONFIG.get('kanidm_client', 'url')
AUTH_URL = "%s/v1/auth" % URL

def _authenticate(s, acct, pw):
    init_auth = {"step": {"init": acct}}

    r = s.post(AUTH_URL, json=init_auth, verify=CA, timeout=TIMEOUT)
    if r.status_code != 200:
        print(r.json())
        raise Exception("AuthInitFailed")

    cred_auth = {"step": { "creds": [{"Password": pw}]}}
    r = s.post(AUTH_URL, json=cred_auth, verify=CA, timeout=TIMEOUT)
    if r.status_code != 200:
        print(r.json())
        raise Exception("AuthCredFailed")

def _get_radius_token(username):
    print("getting rtok for %s ..." % username)
    s = requests.session()
    # First authenticate a connection
    _authenticate(s, USER, SECRET)
    # Now get the radius token
    rtok_url = "%s/v1/account/%s/_radius/_token" % (URL, username)
    r = s.get(rtok_url, verify=CA, timeout=TIMEOUT)
    if r.status_code != 200:
        raise Exception("Failed to get RadiusAuthToken")
    else:
        return r.json()

def check_vlan(acc, group):
    if CONFIG.has_section("group.%s" % group['name']):
        if CONFIG.has_option("group.%s" % group['name'], "vlan"):
            v = CONFIG.get("group.%s" % group['name'], "vlan")
            print("assigning vlan %s from %s" % (v,group))
            return v
    return acc

def instantiate(args):
    print(args)
    return radiusd.RLM_MODULE_OK

def authorize(args):
    radiusd.radlog(radiusd.L_INFO, 'kanidm python module called')

    dargs = dict(args)
    # print(dargs)

    username = dargs['User-Name']

    tok = None

    try:
        tok = _get_radius_token(username)
    except Exception as e:
        print(e)

    if tok == None:
        return radiusd.RLM_MODULE_NOTFOUND

    # print("got token %s" % tok)

    # Are they in the required group?

    req_sat = False
    for group in tok["groups"]:
        if group['name'] == REQ_GROUP:
            req_sat = True
    print("required group satisfied -> %s:%s" % (username, req_sat))
    if req_sat is not True:
        return radiusd.RLM_MODULE_NOTFOUND

    # look up them in config for group vlan if possible.
    uservlan = reduce(check_vlan, tok["groups"], DEFAULT_VLAN)
    if uservlan == 0:
        print("mistake!")
    print("selected vlan %s:%s" % (username, uservlan))
    # Convert the tok groups to groups.
    name = tok["name"]
    secret = tok["secret"]

    reply = (
        ('User-Name', str(name)),
        ('Reply-Message', 'Welcome'),
        ('Tunnel-Type', '13'),
        ('Tunnel-Medium-Type', '6'),
        ('Tunnel-Private-Group-ID', str(uservlan)),
    )
    config = (
        ('Cleartext-Password', str(secret)),
    )

    print("OK! Returning details to radius for %s ..." % username)
    return (radiusd.RLM_MODULE_OK, reply, config)


if __name__ == '__main__':
    # Test getting from the kanidm server instead.
    if len(sys.argv) != 2:
        print("usage: %s username" % sys.argv[0])
    else:
        tok = _get_radius_token(sys.argv[1])
        print(tok)
        print(tok["groups"])

else:
    import radiusd


