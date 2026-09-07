import enum
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import attr
import keyring
import keyring.errors
import pyotp
import structlog
import toml
import xdg.BaseDirectory

logger = structlog.get_logger()

APP_NAME = "openconnect-sso"


def load():
    path = xdg.BaseDirectory.load_first_config(APP_NAME)
    if not path:
        return Config()
    config_path = Path(path) / "config.toml"
    if not config_path.exists():
        return Config()
    with config_path.open() as config_file:
        try:
            cfg = Config.from_dict(toml.load(config_file))
        except Exception:
            logger.error(
                "Could not load configuration file, ignoring",
                path=config_path,
                exc_info=True,
            )
            return Config()
    if _is_superseded(cfg.auto_fill_rules):
        logger.info(
            "Replacing untouched auto-fill rules with the current defaults",
            path=config_path,
        )
        cfg.auto_fill_rules = _converted_default_auto_fill_rules()
    return cfg


def save(config):
    path = xdg.BaseDirectory.save_config_path(APP_NAME)
    config_path = Path(path) / "config.toml"
    try:
        config_path.touch()
        with config_path.open("w") as config_file:
            toml.dump(config.as_dict(), config_file)
    except Exception:
        logger.error(
            "Could not save configuration file", path=config_path, exc_info=True
        )


@attr.s
class ConfigNode:
    @classmethod
    def from_dict(cls, d):
        if d is None:
            return None
        return cls(**d)

    def as_dict(self):
        return attr.asdict(self)


@attr.s
class HostProfile(ConfigNode):
    address = attr.ib(converter=str)
    user_group = attr.ib(converter=str)
    name = attr.ib(converter=str)  # authgroup

    @property
    def vpn_url(self):
        parts = urlparse(self.address)
        group = self.user_group or parts.path
        if parts.path == self.address and not self.user_group:
            group = ""
        return urlunparse(
            (parts.scheme or "https", parts.netloc or self.address, group, "", "", "")
        )


@attr.s
class AutoFillRule(ConfigNode):
    selector = attr.ib()
    fill = attr.ib(default=None)
    action = attr.ib(default=None)
    # Name of a credential (`username`, `password`, `totp`) that has to be
    # available for the rule to be applied at all. Rules guarding a branch of
    # the login flow that only makes sense for a given credential -- like the
    # Entra ID "sign in another way" -> "authenticator code" detour -- use this
    # so that they do not hijack a flow the user wants to complete by hand,
    # such as approving a push notification on their phone.
    requires = attr.ib(default=None)


def get_default_auto_fill_rules():
    return {
        "https://*": [
            AutoFillRule(selector="div[id=passwordError]", action="stop").as_dict(),
            # AD FS shows its error in a container that is always in the DOM,
            # so this only stops the loop once the container is visible.
            AutoFillRule(selector="span[id=errorText]", action="stop").as_dict(),
            AutoFillRule(selector="input[name=loginfmt]", fill="username").as_dict(),
            AutoFillRule(selector="input[type=email]", fill="username").as_dict(),
            AutoFillRule(selector="input[name=passwd]", fill="password").as_dict(),
            # AD FS, which Entra ID hands the password step to for federated
            # domains. Its submit control is a <span>, not a button.
            AutoFillRule(selector="input[id=passwordInput]", fill="password").as_dict(),
            AutoFillRule(
                selector="input[data-report-event=Signin_Submit]", action="click"
            ).as_dict(),
            AutoFillRule(selector="span[id=submitButton]", action="click").as_dict(),
            AutoFillRule(
                selector="div[data-value=PhoneAppOTP]", action="click", requires="totp"
            ).as_dict(),
            AutoFillRule(
                selector="a[id=signInAnotherWay]", action="click", requires="totp"
            ).as_dict(),
            AutoFillRule(
                selector="input[id=idTxtBx_SAOTCC_OTC]", fill="totp", requires="totp"
            ).as_dict(),
        ]
    }


def _converted_default_auto_fill_rules():
    return {
        name: [AutoFillRule.from_dict(r) for r in rules]
        for name, rules in get_default_auto_fill_rules().items()
    }


# Rule sets that earlier versions wrote into config.toml verbatim. A stored set
# that still matches one of these has never been touched by the user, so it is
# safe to replace it with the current defaults instead of leaving the user
# stuck with rules that no longer match the identity provider's login page.
SUPERSEDED_AUTO_FILL_RULES = [
    [
        ("div[id=passwordError]", None, "stop", None),
        ("input[type=email]", "username", None, None),
        ("input[name=passwd]", "password", None, None),
        ("input[data-report-event=Signin_Submit]", None, "click", None),
        ("div[data-value=PhoneAppOTP]", None, "click", None),
        ("a[id=signInAnotherWay]", None, "click", None),
        ("input[id=idTxtBx_SAOTCC_OTC]", "totp", None, None),
    ],
]


def _is_superseded(auto_fill_rules):
    if list(auto_fill_rules) != ["https://*"]:
        return False
    stored = [
        (r.selector, r.fill, r.action, r.requires) for r in auto_fill_rules["https://*"]
    ]
    return stored in SUPERSEDED_AUTO_FILL_RULES


@attr.s
class Credentials(ConfigNode):
    username = attr.ib()

    @property
    def password(self):
        try:
            return keyring.get_password(APP_NAME, self.username)
        except keyring.errors.KeyringError:
            logger.info("Cannot retrieve saved password from keyring.")
            return ""

    @password.setter
    def password(self, value):
        try:
            keyring.set_password(APP_NAME, self.username, value)
        except keyring.errors.KeyringError:
            logger.info("Cannot save password to keyring.")

    @property
    def totp_secret(self):
        """The stored TOTP secret.

        `None` means no answer was ever recorded, an empty string means the
        user explicitly declined to use one -- the two must stay
        distinguishable so that declining is not asked about on every run.
        """
        try:
            return keyring.get_password(APP_NAME, "totp/" + self.username)
        except keyring.errors.KeyringError:
            logger.info("Cannot retrieve saved totp info from keyring.")
            return ""

    @property
    def totp(self):
        totpsecret = self.totp_secret
        return pyotp.TOTP(totpsecret).now() if totpsecret else None

    @totp.setter
    def totp(self, value):
        try:
            keyring.set_password(APP_NAME, "totp/" + self.username, value)
        except keyring.errors.KeyringError:
            logger.info("Cannot save totp secret to keyring.")

    def resolve(self):
        return ResolvedCredentials(self.username, self.password, self.totp)


@attr.s
class ResolvedCredentials:
    """Credential values snapshotted in the main process.

    The browser runs in a separate process; reading the keyring from there
    would open a second session to the secret service, in a process that has no
    terminal to prompt on if it turns out to be locked. The secrets are kept
    out of the `repr` because it is logged when auto-login starts.
    """

    username = attr.ib()
    password = attr.ib(repr=False)
    totp = attr.ib(repr=False, default=None)


@attr.s
class Config(ConfigNode):
    default_profile = attr.ib(default=None, converter=HostProfile.from_dict)
    credentials = attr.ib(default=None, converter=Credentials.from_dict)
    auto_fill_rules = attr.ib(
        factory=get_default_auto_fill_rules,
        converter=lambda rules: {
            n: [AutoFillRule.from_dict(r) for r in rule] for n, rule in rules.items()
        },
    )
    on_disconnect = attr.ib(converter=str, default="")
    # Gateway URL -> the public key pin trusted for it on first use.
    server_certificates = attr.ib(factory=dict)


class DisplayMode(enum.Enum):
    HIDDEN = 0
    SHOWN = 1
