import sys
import os
import subprocess
import atexit
import shutil
import signal


MAJOR, MINOR, _, _, _ = sys.version_info

if MAJOR >= 3:
    import configparser
else:
    import ConfigParser as configparser

DEBUG = True

CONFIG = configparser.ConfigParser()
CONFIG.read('/data/config.ini')

CLIENTS = [
    {
        "name": x.split('.')[1],
        "secret": CONFIG.get(x, "secret"),
        "ipaddr": CONFIG.get(x, "ipaddr"),
    }
    for x in CONFIG.sections()
    if x.startswith('client.')
]

print(CLIENTS)

def _sigchild_handler(*args, **kwargs):
    # log.debug("Received SIGCHLD ...")
    os.waitpid(-1, os.WNOHANG)

def write_clients_conf():
    with open('/etc/raddb/clients.conf', 'w') as f:
        for client in CLIENTS:
            f.write('client %s {\n' % client['name'])
            f.write('    ipaddr = %s\n' % client['ipaddr'])
            f.write('    secret = %s\n' % client['secret'])
            f.write('    proto = *\n')
            f.write('}\n')

def setup_certs():
    # copy ca to /etc/raddb/certs/ca.pem
    shutil.copyfile(CONFIG.get("radiusd", "ca"), '/etc/raddb/certs/ca.pem')
    shutil.copyfile(CONFIG.get("radiusd", "dh"), '/etc/raddb/certs/dh')
    # concat key + cert into /etc/raddb/certs/server.pem
    with open('/etc/raddb/certs/server.pem', 'w') as f:
        with open(CONFIG.get("radiusd", "key"), 'r') as r:
            f.write(r.read())
        f.write('\n')
        with open(CONFIG.get("radiusd", "cert"), 'r') as r:
            f.write(r.read())

def run_radiusd():
    global proc
    if DEBUG:
        proc = subprocess.Popen([
            "/usr/sbin/radiusd", "-X"
        ], stderr=subprocess.STDOUT)
    else:
        proc = subprocess.Popen([
            "/usr/sbin/radiusd", "-f",
            "-l", "stdout"
        ], stderr=subprocess.STDOUT)
    print(proc)

    def kill_radius():
        if proc is None:
            pass
        else:
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except:
                # It's already gone ...
                pass
        print("Stopping radiusd ...")
        # To make sure we really do shutdown, we actually re-block on the proc
        # again here to be sure it's done.
        proc.wait()

    atexit.register(kill_radius)

    proc.wait()

if __name__ == '__main__':
    signal.signal(signal.SIGCHLD, _sigchild_handler)
    setup_certs()
    write_clients_conf()
    run_radiusd()

