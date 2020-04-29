import sys
import requests
import logging
import os
import json

MAJOR, MINOR, _, _, _ = sys.version_info

if MAJOR >= 3:
    import configparser
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
    CA = CONFIG.get("kanidm_client", "ca")
else:
    CA = False
USER = CONFIG.get("kanidm_client", "user")
SECRET = CONFIG.get("kanidm_client", "secret")
DEFAULT_VLAN = CONFIG.get("radiusd", "vlan")
CACHE_PATH = CONFIG.get("radiusd", "cache_path")
TIMEOUT = 8

URL = CONFIG.get('kanidm_client', 'url')
AUTH_URL = "%s/v1/auth" % URL

def _authenticate(s, acct, pw):
    init_auth = {"step": { "Init": [acct, None]}}

    r = s.post(AUTH_URL, json=init_auth, verify=CA, timeout=TIMEOUT)
    if r.status_code != 200:
        print(r.json())
        raise Exception("AuthInitFailed")

    cred_auth = {"step": { "Creds": [{"Password": pw}]}}
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
    tok = r.json()
    return(tok)

def _update_cache(token):
    # Ensure the dir exists
    try:
        os.makedirs(CACHE_PATH, mode=0o700)
    except:
        # Already exists
        pass
    # User Item
    item = os.path.join(CACHE_PATH, token["uuid"])
    uitem = os.path.join(CACHE_PATH, token["name"])
    # Token to json.
    with open(item, 'w') as f:
        json.dump(token, f)
    # Symlink username -> uuid
    try:
        os.symlink(item, uitem)
    except Exception as e:
        print(e)

def _get_cache(username):
    print("Getting cached token ...")
    uitem = os.path.join(CACHE_PATH, username)
    try:
        with open(uitem, 'r') as f: 
            return json.load(f)
    except:
        None

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
        # Update the cache?
        _update_cache(tok)
    except Exception as e:
        print(e)
        # Attempt the cache.
        tok = _get_cache(username)

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


