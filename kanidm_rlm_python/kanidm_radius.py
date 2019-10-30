import sys
import requests
# import radiusd

# Setup the config too

def _get_radius_token(username):
    print("getting rtok for %s ..." % username)
    pass

def instantiate(args):
    print(args)
    return radiusd.RLM_MODULE_OK

def authorize(args):
    radiusd.radlog(radiusd.L_INFO, 'kanidm python module called')

    dargs = dict(args)
    print(dargs)

    username = dargs['User-Name']

    userrec = USERS.get(username, None)
    if userrec is None:
        return radiusd.RLM_MODULE_NOTFOUND

    (usernthash, uservlan) = userrec

    reply = (
        ('Reply-Message', 'Welcome'),
        ('Group', 'Group-A'),
        ('Tunnel-Type', '13'),
        ('Tunnel-Medium-Type', '6'),
        ('Tunnel-Private-Group-ID', uservlan),
    )
    config = (
        ('NT-Password', usernthash),
    )

    return (radiusd.RLM_MODULE_OK, reply, config)


if __name__ == '__main__':
    # Test getting from the kanidm server instead.
    if len(sys.argv) != 2:
        print("usage: %s username" % sys.argv[0])
    else:
        _get_radius_token(sys.argv[1])

else:
    import radiusd


