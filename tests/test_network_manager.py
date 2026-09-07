import pytest

from openconnect_sso import network_manager


@pytest.mark.parametrize(
    "vpn_url,expected",
    [
        ("https://vpn.example.com/group", "vpn.example.com/group"),
        ("https://vpn.example.com", "vpn.example.com"),
        ("https://vpn.example.com:4443/group", "vpn.example.com:4443/group"),
        ("vpn.example.com", "vpn.example.com"),
    ],
)
def test_gateway_is_stored_without_the_scheme(vpn_url, expected):
    assert network_manager._split_gateway(vpn_url) == expected


def test_secrets_are_passed_in_a_private_file_and_not_on_the_command_line(
    monkeypatch, tmp_path
):
    calls = []

    def fake_nmcli(*args, **kwargs):
        calls.append(args)
        passwd_file = args[args.index("passwd-file") + 1]
        stat = __import__("os").stat(passwd_file)
        assert stat.st_mode & 0o077 == 0, "secrets file is readable by others"
        with open(passwd_file) as f:
            fake_nmcli.secrets = f.read()
        return __import__("subprocess").CompletedProcess(args, 0, b"", b"")

    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(network_manager, "_nmcli", fake_nmcli)

    network_manager.activate(
        "VPN", "https://vpn.example.com/group", "cookie-value", "pin-sha256:abcd"
    )

    assert "cookie-value" not in str(calls)
    assert fake_nmcli.secrets == (
        "vpn.secrets.gateway:https://vpn.example.com/group\n"
        "vpn.secrets.cookie:cookie-value\n"
        "vpn.secrets.gwcert:pin-sha256:abcd\n"
    )


def test_missing_connection_is_not_created_when_creation_is_disabled(monkeypatch):
    monkeypatch.setattr(network_manager, "connection_exists", lambda name: False)
    with pytest.raises(network_manager.NetworkManagerError):
        network_manager.connect(
            "VPN",
            "cookie",
            "pin-sha256:abcd",
            "https://a/g",
            "https://b/g",
            "4.7.00136",
            create=False,
        )


def test_active_connection_is_restarted_with_the_fresh_cookie(monkeypatch):
    order = []
    monkeypatch.setattr(network_manager, "connection_exists", lambda name: True)
    monkeypatch.setattr(network_manager, "is_active", lambda name: True)
    monkeypatch.setattr(
        network_manager, "deactivate", lambda name: order.append("down")
    )
    monkeypatch.setattr(network_manager, "activate", lambda *a: order.append("up"))

    network_manager.connect(
        "VPN", "cookie", "pin-sha256:abcd", "https://a/g", "https://b/g", "4.7.00136"
    )

    assert order == ["down", "up"]
