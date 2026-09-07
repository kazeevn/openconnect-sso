import keyring
import pytest

from openconnect_sso import config


class InMemoryKeyring(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self):
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        del self.store[(service, username)]


@pytest.fixture
def in_memory_keyring(monkeypatch):
    backend = InMemoryKeyring()
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend)
    monkeypatch.setattr(keyring, "get_password", backend.get_password)
    monkeypatch.setattr(keyring, "set_password", backend.set_password)
    return backend


def test_password_comes_from_the_keyring(in_memory_keyring):
    in_memory_keyring.set_password(config.APP_NAME, "user", "from-keyring")
    assert config.Credentials("user").password == "from-keyring"


def test_resolved_credentials_keep_secrets_out_of_the_repr(in_memory_keyring):
    # The repr is logged when auto-login starts.
    in_memory_keyring.set_password(config.APP_NAME, "user", "s3cr3t")
    resolved = repr(config.Credentials("user").resolve())
    assert "user" in resolved
    assert "s3cr3t" not in resolved


def test_declined_totp_is_remembered(in_memory_keyring):
    credentials = config.Credentials("user")
    assert credentials.totp_secret is None
    credentials.totp = ""
    assert credentials.totp_secret == ""
    assert credentials.totp is None


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Point both the load and the save path at a throwaway directory.

    Both, always: patching only one of them makes `config.save()` overwrite the
    real configuration file of whoever runs the tests.
    """
    path = tmp_path / "openconnect-sso"
    path.mkdir()
    monkeypatch.setattr(
        config.xdg.BaseDirectory, "load_first_config", lambda _: str(path)
    )
    monkeypatch.setattr(
        config.xdg.BaseDirectory, "save_config_path", lambda _: str(path)
    )
    return path


def test_untouched_legacy_auto_fill_rules_are_upgraded(config_dir):
    legacy = config.Config()
    legacy.auto_fill_rules = {
        "https://*": [
            config.AutoFillRule(selector, fill, action)
            for selector, fill, action, _ in config.SUPERSEDED_AUTO_FILL_RULES[0]
        ]
    }
    config.save(legacy)
    # `pass` for the second factor is the point of the upgrade: the OTP detour
    # must no longer be clicked when no TOTP secret is configured.
    upgraded = config.load().auto_fill_rules["https://*"]
    assert [r.requires for r in upgraded if r.selector == "a[id=signInAnotherWay]"] == [
        "totp"
    ]


def test_customized_auto_fill_rules_are_left_alone(config_dir):
    customized = config.Config()
    customized.auto_fill_rules = {
        "https://*": [config.AutoFillRule("input[name=user]", fill="username")]
    }
    config.save(customized)

    rules = config.load().auto_fill_rules["https://*"]
    assert [r.selector for r in rules] == ["input[name=user]"]
