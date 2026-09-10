#!/usr/bin/env python3

import argparse
import enum
import logging
import os
import sys

import openconnect_sso
from openconnect_sso import app, config, __version__


def create_argparser():
    parser = argparse.ArgumentParser(
        prog="openconnect-sso", description=openconnect_sso.__description__
    )

    server_settings = parser.add_argument_group("Server connection")
    server_settings.add_argument(
        "-p",
        "--profile",
        dest="profile_path",
        help="Use a profile from this file or directory",
    )

    server_settings.add_argument(
        "-P",
        "--profile-selector",
        dest="use_profile_selector",
        help="Always display profile selector",
        action="store_true",
        default=False,
    )

    server_settings.add_argument("--proxy", help="Use a proxy server")

    server_settings.add_argument(
        "-s",
        "--server",
        help="VPN server to connect to. The following forms are accepted: "
        "vpn.server.com, vpn.server.com/usergroup, "
        "https://vpn.server.com, https.vpn.server.com.usergroup",
    )

    auth_settings = parser.add_argument_group(
        "Authentication",
        "Used for the same purpose as in OpenConnect. Refer to OpenConnect's documentation for further information",
    )

    auth_settings.add_argument(
        "--authgroup",
        help="Set to the required authentication login selection",
        default="",
    )

    auth_settings.add_argument(
        "-g",
        "--usergroup",
        help="Override usergroup setting from --server argument",
        default="",
    )

    auth_settings.add_argument(
        "--authenticate",
        help="Authenticate only, and output the information needed to make the connection. Output formatting choices: {%(choices)s}",
        choices=["shell", "json"],
        const="shell",
        metavar="OUTPUT-FORMAT",
        nargs="?",
        default=False,
    )

    parser.add_argument(
        "--browser-display-mode",
        help="Controls how the browser window is displayed. 'hidden' mode only works with saved credentials. Choices: {%(choices)s}",
        choices=["shown", "hidden"],
        metavar="DISPLAY-MODE",
        nargs="?",
        default="shown",
    )

    parser.add_argument(
        "--on-disconnect",
        help="Command to run when disconnecting from VPN server",
        default="",
    )

    nm_settings = parser.add_argument_group(
        "NetworkManager",
        "Let NetworkManager own the tunnel instead of running openconnect directly. "
        "The authenticated session is handed to NetworkManager's openconnect plugin, "
        "so the connection shows up in the desktop applet and is torn down with "
        "`nmcli connection down`.",
    )
    nm_settings.add_argument(
        "-N",
        "--network-manager",
        dest="network_manager",
        help="Connect through NetworkManager. Optionally takes the name of the "
        "NetworkManager VPN connection to activate, defaulting to the profile name. "
        "The connection is created if it does not exist yet.",
        metavar="CONNECTION-NAME",
        nargs="?",
        const=True,
        default=None,
    )
    nm_settings.add_argument(
        "--no-nm-create",
        dest="nm_create",
        help="Fail instead of creating the NetworkManager connection when it is missing",
        action="store_false",
        default=True,
    )

    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    parser.add_argument(
        "--ac-version",
        help="AnyConnect Version used for authentication and for OpenConnect, defaults to %(default)s",
        default="4.7.00136",
    )

    parser.add_argument(
        "-l",
        "--log-level",
        help="",
        type=LogLevel.parse,
        choices=LogLevel.choices(),
        default=LogLevel.INFO,
    )

    parser.add_argument(
        "openconnect_args",
        help="Arguments passed to openconnect",
        action=StoreOpenConnectArgs,
        nargs=argparse.REMAINDER,
    )

    credentials_group = parser.add_argument_group("Credentials for automatic login")
    credentials_group.add_argument(
        "-u", "--user", help="Authenticate as the given user", default=None
    )
    credentials_group.add_argument(
        "--no-totp",
        help="Never ask for or use a TOTP secret. Use this when the second factor "
        "is approved out of band, for example a push notification",
        action="store_true",
        default=False,
    )
    return parser


class StoreOpenConnectArgs(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if "--" in values:
            values.remove("--")
        setattr(namespace, self.dest, values)


class LogLevel(enum.IntEnum):
    ERROR = logging.ERROR
    WARNING = logging.WARNING
    INFO = logging.INFO
    DEBUG = logging.DEBUG

    def __str__(self):
        return self.name

    @classmethod
    def parse(cls, name):
        try:
            level = cls.__members__[name.upper()]
        except KeyError:
            print(f"unknown loglevel '{name}', setting to INFO", file=sys.stderr)
            level = logging.INFO
        return level

    @classmethod
    def choices(cls):
        return cls.__members__.values()


def main():
    parser = create_argparser()
    args = parser.parse_args()

    if (args.profile_path or args.use_profile_selector) and (
        args.server or args.usergroup
    ):
        parser.error(
            "--profile/--profile-selector and --server/--usergroup are mutually exclusive"
        )

    if not args.profile_path and not args.server and not config.load().default_profile:
        if os.path.exists("/opt/cisco/anyconnect/profile"):
            args.profile_path = "/opt/cisco/anyconnect/profile"
        else:
            parser.error(
                "No AnyConnect profile can be found. One of --profile or --server arguments required."
            )

    if args.use_profile_selector and not args.profile_path:
        parser.error(
            "No AnyConnect profile can be found. --profile argument is required."
        )

    return app.run(args)


if __name__ == "__main__":
    sys.exit(main())
