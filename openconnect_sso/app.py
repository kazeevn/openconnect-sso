import asyncio
import getpass
import json
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path

import shlex
import shutil
import structlog
from prompt_toolkit import HTML
from prompt_toolkit.shortcuts import radiolist_dialog

from openconnect_sso import config, network_manager
from openconnect_sso.authenticator import Authenticator, AuthResponseError
from openconnect_sso.browser import Terminated
from openconnect_sso.config import Credentials
from openconnect_sso.network_manager import NetworkManagerError
from openconnect_sso.profile import get_profiles

from requests.exceptions import HTTPError

logger = structlog.get_logger()


def run(args):
    configure_logger(logging.getLogger(), args.log_level)

    cfg = config.load()

    try:
        if os.name == "nt":
            asyncio.set_event_loop(asyncio.ProactorEventLoop())
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        auth_response, selected_profile, profile_address = loop.run_until_complete(
            _run(args, cfg)
        )
    except KeyboardInterrupt:
        logger.warn("CTRL-C pressed, exiting")
        return 130
    except ValueError as e:
        msg, retval = e.args
        logger.error(msg)
        return retval
    except Terminated:
        logger.warn("Browser window terminated, exiting")
        return 2
    except AuthResponseError as exc:
        logger.error(
            f'Required attributes not found in response ("{exc}", does this endpoint do SSO?), exiting'
        )
        return 3
    except HTTPError as exc:
        logger.error(f"Request error: {exc}")
        return 4
    except NetworkManagerError as exc:
        logger.error(f"NetworkManager error: {exc}")
        return 5

    config.save(cfg)

    if args.authenticate:
        logger.warn("Exiting after login, as requested")
        details = {
            "host": selected_profile.vpn_url,
            "cookie": auth_response.session_token,
            "fingerprint": auth_response.server_cert_hash,
        }
        if args.authenticate == "json":
            print(json.dumps(details, indent=4))
        elif args.authenticate == "shell":
            print(
                "\n".join(f"{k.upper()}={shlex.quote(v)}" for k, v in details.items())
            )
        return 0

    if args.network_manager:
        if args.openconnect_args:
            logger.warn(
                "Ignoring openconnect arguments, NetworkManager runs openconnect",
                args=args.openconnect_args,
            )
        connection_name = (
            selected_profile.name
            if args.network_manager is True
            else args.network_manager
        )
        try:
            return network_manager.connect(
                connection_name,
                auth_response.session_token,
                auth_response.server_cert_hash,
                selected_profile.vpn_url,
                profile_address.vpn_url,
                args.ac_version,
                create=args.nm_create,
            )
        except NetworkManagerError as exc:
            logger.error(f"NetworkManager error: {exc}")
            return 5

    try:
        return run_openconnect(
            auth_response.session_token,
            auth_response.server_cert_hash,
            selected_profile,
            args.proxy,
            args.ac_version,
            args.openconnect_args,
        )
    except KeyboardInterrupt:
        logger.warn("CTRL-C pressed, exiting")
        return 0
    finally:
        handle_disconnect(cfg.on_disconnect)


def configure_logger(logger, level):
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer()
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)


async def _run(args, cfg):
    credentials = None
    if cfg.credentials:
        credentials = cfg.credentials
        if args.user and args.user != credentials.username:
            credentials = Credentials(args.user)
    elif args.user:
        credentials = Credentials(args.user)

    if credentials:
        setup_credentials(args, cfg, credentials)

    if cfg.default_profile and not (args.use_profile_selector or args.server):
        selected_profile = cfg.default_profile
    elif args.use_profile_selector or args.profile_path:
        profiles = get_profiles(Path(args.profile_path))
        if not profiles:
            raise ValueError("No profile found", 17)

        selected_profile = await select_profile(profiles)
        if not selected_profile:
            raise ValueError("No profile selected", 18)
    elif args.server:
        selected_profile = config.HostProfile(
            args.server, args.usergroup, args.authgroup
        )
    else:
        raise ValueError(
            "Cannot determine server address. Invalid arguments specified.", 19
        )

    cfg.default_profile = config.HostProfile(
        selected_profile.address, selected_profile.user_group, selected_profile.name
    )

    display_mode = config.DisplayMode[args.browser_display_mode.upper()]

    auth_response = await authenticate_to(
        selected_profile, args.proxy, credentials, display_mode, args.ac_version
    )

    if args.on_disconnect and not cfg.on_disconnect:
        cfg.on_disconnect = args.on_disconnect

    return auth_response, selected_profile, cfg.default_profile


def setup_credentials(args, cfg, credentials):
    """Complete `credentials` from the keyring, asking for what is missing."""
    if not credentials.password:
        if not sys.stdin.isatty():
            raise ValueError(
                f"No password saved for {credentials.username} and cannot ask for one. "
                "Run openconnect-sso from a terminal once to save it in the keyring",
                21,
            )
        credentials.password = getpass.getpass(
            prompt=f"Password ({credentials.username}): "
        )

    if args.no_totp:
        if credentials.totp_secret:
            # Recorded so that subsequent runs neither ask nor use it.
            credentials.totp = ""
    elif credentials.totp_secret is None and sys.stdin.isatty():
        credentials.totp = getpass.getpass(
            prompt=f"TOTP secret (leave blank if not required) ({credentials.username}): "
        )

    cfg.credentials = credentials


async def select_profile(profile_list):
    selection = await radiolist_dialog(
        title="Select AnyConnect profile",
        text=HTML(
            "The following AnyConnect profiles are detected.\n"
            "The selection will be <b>saved</b> and not asked again unless the <pre>--profile-selector</pre> command line option is used"
        ),
        values=[(p, p.name) for i, p in enumerate(profile_list)],
    ).run_async()
    # Somehow prompt_toolkit sets up a bogus signal handler upon exit
    # TODO: Report this issue upstream
    if hasattr(signal, "SIGWINCH"):
        asyncio.get_event_loop().remove_signal_handler(signal.SIGWINCH)
    if not selection:
        return selection
    logger.info("Selected profile", profile=selection.name)
    return selection


def authenticate_to(host, proxy, credentials, display_mode, version):
    logger.info("Authenticating to VPN endpoint", name=host.name, address=host.address)
    return Authenticator(
        host, proxy, credentials.resolve() if credentials else None, version
    ).authenticate(display_mode)


def run_openconnect(session_token, server_cert, host, proxy, version, args):
    as_root = next(([prog] for prog in ("doas", "sudo") if shutil.which(prog)), [])
    try:
        if not as_root:
            if os.name == "nt":
                import ctypes

                if not ctypes.windll.shell32.IsUserAnAdmin():
                    raise PermissionError
            else:
                raise PermissionError
    except PermissionError:
        logger.error(
            "Cannot find suitable program to execute as superuser (doas/sudo), exiting"
        )
        return 20

    command_line = as_root + [
        "openconnect",
        "--useragent",
        f"AnyConnect Linux_64 {version}",
        "--version-string",
        version,
        "--cookie-on-stdin",
        "--servercert",
        server_cert,
        *args,
        host.vpn_url,
    ]
    if proxy:
        command_line.extend(["--proxy", proxy])

    logger.debug("Starting OpenConnect", command_line=command_line)
    return subprocess.run(command_line, input=session_token.encode("utf-8")).returncode


def handle_disconnect(command):
    if command:
        logger.info("Running command on disconnect", command_line=command)
        return subprocess.run(command, timeout=5, shell=True).returncode
