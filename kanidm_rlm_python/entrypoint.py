""" entrypoint for kanidm's RADIUS module """

import atexit
import os
from pathlib import Path
import subprocess
import shutil
import signal
import sys
from typing import Any

# import toml
from kanidm.types import KanidmClientConfig
from kanidm.utils import load_config

DEBUG = True
if os.environ.get('DEBUG', False):
    DEBUG = True

CONFIG_FILE_PATH = "/data/kanidm"

CERT_SERVER_DEST = "/etc/raddb/certs/server.pem"
CERT_CA_DEST = "/etc/raddb/certs/ca.pem"
CERT_DH_DEST = "/etc/raddb/certs/dh.pem"

# pylint: disable=unused-argument
def _sigchild_handler(
    *args: Any,
    **kwargs: Any,
    ) -> None:
    """ handler for SIGCHLD call"""
    print("Received SIGCHLD ...", file=sys.stderr)
    os.waitpid(-1, os.WNOHANG)

def write_clients_conf(
    kanidm_config_object: KanidmClientConfig,
    ) -> None:
    """ writes out the config file """
    raddb_config_file = Path("/etc/raddb/clients.conf")

    with raddb_config_file.open('w', encoding='utf-8') as file_handle:
        for client in kanidm_config_object.radius_clients:
            file_handle.write(f"client {client.name} {{\n" )
            file_handle.write(f"    ipaddr = {client.ipaddr}\n")
            file_handle.write(f"    secret = {client.secret}\n" )
            file_handle.write('    proto = *\n')
            file_handle.write('}\n')

def setup_certs(
    kanidm_config_object: KanidmClientConfig,
    ) -> None:
    """ sets up certificates """
    print(kanidm_config_object)
    # sys.exit(1)

    if kanidm_config_object.radius_ca_path:
        cert_ca = Path(kanidm_config_object.radius_ca_path).expanduser().resolve()
        if not cert_ca.exists():
            print(f"Failed to find radiusd ca file ({cert_ca}), quitting!", file=sys.stderr)
            sys.exit(1)
        if cert_ca != CERT_CA_DEST:
            print(f"Copying {cert_ca} to {CERT_CA_DEST}")
            shutil.copyfile(cert_ca, CERT_CA_DEST)

    # let's put some dhparams in place
    if kanidm_config_object.radius_dh_path is not None:
        cert_dh = Path(kanidm_config_object.radius_dh_path).expanduser().resolve()
        if not cert_dh.exists():
            print(f"Failed to find radiusd dh file ({cert_dh}), quitting!", file=sys.stderr)
            sys.exit(1)
        if cert_dh != CERT_DH_DEST:
            print(f"Copying {cert_dh} to {CERT_DH_DEST}")
            shutil.copyfile(cert_dh, CERT_DH_DEST)

    server_key = Path(kanidm_config_object.radius_key_path).expanduser().resolve()
    if not server_key.exists() or not server_key.is_file():
        print(
            f"Failed to find server keyfile ({server_key}), quitting!",
            file=sys.stderr,
            )
        sys.exit(1)

    server_cert = Path(kanidm_config_object.radius_cert_path).expanduser().resolve()
    if not server_cert.exists() or not server_cert.is_file():
        print(
            f"Failed to find server cert file ({server_cert}), quitting!",
            file=sys.stderr,
            )
        sys.exit(1)
    # concat key + cert into /etc/raddb/certs/server.pem
    with open(CERT_SERVER_DEST, 'w', encoding='utf-8') as file_handle:
        file_handle.write(server_cert.read_text(encoding="utf-8"))
        file_handle.write('\n')
        file_handle.write(server_key.read_text(encoding="utf-8"))

def kill_radius(
    proc: subprocess.Popen,
    ) -> None:
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

    config_file = Path(CONFIG_FILE_PATH).expanduser().resolve()
    if not config_file.exists:
        print(
            "Failed to find configuration file ({config_file}), quitting!",
            file=sys.stderr,
            )
        sys.exit(1)

    kanidm_config = KanidmClientConfig.parse_obj(load_config(CONFIG_FILE_PATH))
    setup_certs(kanidm_config)
    write_clients_conf(kanidm_config)
    print("Configuration set up, starting...")
    try:
        run_radiusd()
    except KeyboardInterrupt as ki:
        print(ki)
