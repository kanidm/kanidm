""" entrypoing for kanidm's RADIUS module """

import atexit
import configparser
import os
from pathlib import Path
import subprocess
import shutil
import signal
import sys
from typing import Any, Dict, List

import toml

DEBUG = True
if os.environ.get('DEBUG', False):
    DEBUG = True

def load_config_file(filename: str) -> Any:
    """ loading the TOML config """
    with Path(filename).expanduser().resolve() as filepath:
        return toml.load(filepath)

config_file = Path("/data/config.ini").expanduser().resolve()
if not config_file.exists:
    print(
        "Failed to find configuration file ({config_file}), quitting!",
        file=sys.stderr,
        )
    sys.exit(1)

CONFIG = configparser.ConfigParser(
    interpolation=None,
)
CONFIG.read('/data/config.ini')


def generate_clients(config_object: configparser.ConfigParser) -> List[Dict[str, str]]:
    """ generates the list of clients to handle later """
    return [
        {
            "name": x.split('.')[1],
            "secret": config_object.get(x, "secret"),
            "ipaddr": config_object.get(x, "ipaddr"),
        }
        for x in config_object.sections()
        if x.startswith('client.')
    ]


def _sigchild_handler(*args: Any, **kwargs: Any) -> None: # pylint: disable=unused-argument
    """ handler for SIGCHLD call"""
    print("Received SIGCHLD ...", file=sys.stderr)
    os.waitpid(-1, os.WNOHANG)

def write_clients_conf(client_configs: List[Dict[str, str]]) -> None:
    """ writes out the config file """
    raddb_config_file = Path("/etc/raddb/clients.conf")

    with raddb_config_file.open('w', encoding='utf-8') as file_handle:
        for client in client_configs:
            file_handle.write(f"client {client['name']} {{\n" )
            file_handle.write(f"    ipaddr = {client['ipaddr']}\n")
            file_handle.write(f"    secret = {client['secret']}\n" )
            file_handle.write('    proto = *\n')
            file_handle.write('}\n')

def setup_certs() -> None:
    """ sets up certificates """
    # copy ca to /etc/raddb/certs/ca.pem
    if CONFIG.get("radiusd", "ca", fallback="") != "":
        cert_ca = Path(CONFIG.get("radiusd", "ca")).expanduser().resolve()
        if not cert_ca.exists():
            print(f"Failed to find radiusd ca file ({cert_ca}), quitting!", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Looking for cert_ca in {cert_ca}", file=sys.stderr )
        shutil.copyfile(cert_ca, '/etc/raddb/certs/ca.pem')
    if CONFIG.get("radiusd", "dh", fallback="") != "":
        cert_dh = Path(CONFIG.get("radiusd", "dh")).expanduser().resolve()
        if not cert_dh.exists():
            print(f"Failed to find radiusd dh file ({cert_dh}), quitting!", file=sys.stderr)
            sys.exit(1)
        shutil.copyfile(cert_dh, '/etc/raddb/certs/dh')

    server_key = Path(
        CONFIG.get(
            "radiusd",
            "key",
            fallback="/etc/raddb/certs/key.pem")
        ).expanduser().resolve()
    if not server_key.exists() or not server_key.is_file():
        print(
            f"Failed to find server keyfile ({server_key}), quitting!",
            file=sys.stderr,
            )
        sys.exit(1)

    server_cert = Path(
        CONFIG.get(
            "radiusd",
            "cert",
            fallback="/etc/raddb/certs/chain.pem")
        ).expanduser().resolve()
    if not server_cert.exists() or not server_cert.is_file():
        print(
            f"Failed to find server cert file ({server_cert}), quitting!",
            file=sys.stderr,
            )
        sys.exit(1)
    # concat key + cert into /etc/raddb/certs/server.pem
    with open('/etc/raddb/certs/server.pem', 'w', encoding='utf-8') as file_handle:
        file_handle.write(server_cert.read_text(encoding="utf-8"))
        file_handle.write('\n')
        file_handle.write(server_key.read_text(encoding="utf-8"))

def kill_radius(proc: subprocess.Popen) -> None:
    """ handler to kill the radius server once the script exits """
    if proc is None:
        pass
    else:
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except OSError:
            print("sever is already gone...", file=sys.stderr)
    print("Stopping radiusd ...", file=sys.stderr)
    # To make sure we really do shutdown, we actually re-block on the proc
    # again here to be sure it's done.

    # TODO: returns the return code of the process, do we want to log it, or exit with the code
    proc.wait()

def run_radiusd() -> None:
    """ run the server """

    if DEBUG:
        cmd_args = [ "-X" ]
    else:
        cmd_args = [ "-f", "-l", "stdout" ]
    with subprocess.Popen(
        ["/usr/sbin/radiusd"] + cmd_args,
        stderr=subprocess.STDOUT,
        ) as proc:
        # print(proc, file=sys.stderr)
        atexit.register(kill_radius, proc)
        proc.wait()

if __name__ == '__main__':
    signal.signal(signal.SIGCHLD, _sigchild_handler)
    setup_certs()
    # TODO: change this to not-a-global
    write_clients_conf(generate_clients(CONFIG))
    print("Configuration set up, starting...")
    try:
        run_radiusd()
    except KeyboardInterrupt as ki:
        print(ki)
