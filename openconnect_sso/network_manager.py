"""Hand an SSO-authenticated session over to NetworkManager.

`openconnect-sso` normally runs `openconnect` itself, which means the tunnel is
owned by the terminal it was started from and is invisible to the desktop.
NetworkManager can own it instead: its `openconnect` VPN plugin accepts the
session cookie, the gateway and the server certificate hash as *secrets*, which
is exactly what a successful SSO login produces. Supplying them through
`nmcli connection up ... passwd-file` replaces the graphical authentication
dialog that would otherwise pop up, and from then on the connection is a normal
NetworkManager VPN: it shows up in the applet, NetworkManager owns routing and
DNS, and it is torn down with `nmcli connection down`.
"""

import getpass
import os
import shutil
import socket
import subprocess
import tempfile
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()

VPN_TYPE = "openconnect"

# NM_SETTING_SECRET_FLAG_NOT_SAVED: NetworkManager never stores the secret and
# asks a secret agent for it on every activation. `nmcli ... passwd-file` acts
# as that agent, so nothing sensitive ends up in the connection profile.
NOT_SAVED = 2


class NetworkManagerError(Exception):
    pass


def _nmcli(*args, **kwargs):
    nmcli = shutil.which("nmcli")
    if not nmcli:
        raise NetworkManagerError(
            "Cannot find nmcli, is NetworkManager installed and in PATH?"
        )
    command_line = [nmcli, *args]
    logger.debug("Running nmcli", command_line=command_line)
    return subprocess.run(command_line, **kwargs)


def _split_gateway(vpn_url):
    """Turn a VPN URL into the `host[:port]/usergroup` form nmcli expects."""
    parts = urlparse(vpn_url)
    netloc = parts.netloc or parts.path
    group = parts.path.lstrip("/") if parts.netloc else ""
    return f"{netloc}/{group}" if group else netloc


def connection_exists(name):
    result = _nmcli(
        "-t",
        "-f",
        "NAME",
        "connection",
        "show",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise NetworkManagerError("Could not list NetworkManager connections")
    return name in result.stdout.decode("utf-8").splitlines()


def is_active(name):
    result = _nmcli(
        "-t",
        "-f",
        "NAME",
        "connection",
        "show",
        "--active",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return False
    return name in result.stdout.decode("utf-8").splitlines()


def create_connection(name, vpn_url, version):
    """Create a VPN profile that expects its secrets from a secret agent."""
    gateway = _split_gateway(vpn_url)
    # Everything the graphical editor writes for an AnyConnect profile, with
    # every secret marked as not-saved so that activation asks us for them.
    vpn_data = ",".join(
        [
            f"gateway={gateway}",
            "protocol=anyconnect",
            "authtype=password",
            "enable_csd_trojan=no",
            "disable_udp=no",
            "pem_passphrase_fsid=no",
            "prevent_invalid_cert=no",
            "stoken_source=disabled",
            f"useragent=AnyConnect Linux_64 {version}",
            f"gateway-flags={NOT_SAVED}",
            f"cookie-flags={NOT_SAVED}",
            f"gwcert-flags={NOT_SAVED}",
            f"resolve-flags={NOT_SAVED}",
        ]
    )
    logger.info("Creating NetworkManager VPN connection", name=name, gateway=gateway)
    result = _nmcli(
        "connection",
        "add",
        "type",
        "vpn",
        "con-name",
        name,
        "vpn-type",
        VPN_TYPE,
        "--",
        "vpn.data",
        vpn_data,
        # Only this user can see and activate the connection, and only through
        # a fresh SSO login: autoconnecting would just raise the graphical
        # authentication dialog this whole path exists to avoid.
        "connection.permissions",
        f"user:{getpass.getuser()}",
        "connection.autoconnect",
        "no",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise NetworkManagerError(
            "Could not create NetworkManager connection: "
            + result.stderr.decode("utf-8", "replace").strip()
        )


def _resolve(vpn_url):
    """`host:ip` for openconnect's --resolve, or None if it cannot be looked up.

    The plugin asks for this secret whenever `resolve-flags` is set, and nmcli
    refuses to activate a connection whose secrets it cannot fully supply. It
    also pins the connection to the load-balanced host the SSO session was
    actually established with, which is the one holding the cookie.
    """
    host = urlparse(vpn_url).hostname
    if not host:
        return None
    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError):
        logger.warn("Could not resolve VPN gateway address", host=host)
        return None
    return f"{host}:{address}"


def activate(name, vpn_url, cookie, server_cert_hash):
    lines = [
        f"vpn.secrets.gateway:{vpn_url}",
        f"vpn.secrets.cookie:{cookie}",
        f"vpn.secrets.gwcert:{server_cert_hash}",
    ]
    resolve = _resolve(vpn_url)
    if resolve:
        lines.append(f"vpn.secrets.resolve:{resolve}")
    secrets = "\n".join(lines + [""])
    # $XDG_RUNTIME_DIR is a user-private tmpfs, so the cookie never reaches a
    # world-readable directory or a disk.
    with tempfile.TemporaryDirectory(
        dir=os.environ.get("XDG_RUNTIME_DIR") or None, prefix="openconnect-sso-"
    ) as tmpdir:
        passwd_file = os.path.join(tmpdir, "secrets")
        fd = os.open(passwd_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets)

        logger.info("Activating NetworkManager VPN connection", name=name)
        result = _nmcli(
            "connection",
            "up",
            "id",
            name,
            "passwd-file",
            passwd_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        raise NetworkManagerError(
            "Could not activate NetworkManager connection: "
            + result.stderr.decode("utf-8", "replace").strip()
        )
    logger.info(
        "VPN connection is up",
        name=name,
        detail=result.stdout.decode("utf-8", "replace").strip(),
    )


def deactivate(name):
    logger.info("Deactivating stale NetworkManager VPN connection", name=name)
    _nmcli(
        "connection",
        "down",
        "id",
        name,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def connect(name, auth_info, connect_url, profile_url, version, create=True):
    """Bring up `name`, creating it from the profile first if it is missing.

    `connect_url` is the -- possibly load-balanced -- host the SSO session was
    established with and is what `openconnect` has to talk to; `profile_url` is
    the stable address from the AnyConnect profile and is what gets stored in
    the connection so that it stays usable from the desktop applet too.
    """
    if not connection_exists(name):
        if not create:
            raise NetworkManagerError(
                f"NetworkManager connection {name!r} does not exist"
            )
        create_connection(name, profile_url, version)
    if is_active(name):
        deactivate(name)
    activate(name, connect_url, auth_info.session_token, auth_info.server_cert_hash)
    return 0
