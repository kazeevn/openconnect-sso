import attr

from openconnect_sso.browser.webengine_process import get_selectors
from openconnect_sso.config import AutoFillRule


@attr.s
class Credentials:
    username = attr.ib(default="user@example.com")
    password = attr.ib(default="s3cr3t")
    totp = attr.ib(default=None)


def test_fill_uses_the_native_setter_so_that_frameworks_notice():
    script = get_selectors(
        [AutoFillRule(selector="input[name=passwd]", fill="password")], Credentials()
    )
    assert 'ocssFill(elem, "input[name=passwd]", "s3cr3t")' in script


def test_missing_credential_is_not_filled_as_null():
    script = get_selectors(
        [AutoFillRule(selector="input[id=otc]", fill="totp")], Credentials()
    )
    assert script == ""


def test_click_is_deferred_to_the_pass_after_a_fill():
    script = get_selectors(
        [
            AutoFillRule(selector="input[name=passwd]", fill="password"),
            AutoFillRule(selector="input[type=submit]", action="click"),
        ],
        Credentials(),
    )
    fill, click = script.splitlines()
    assert "filled = ocssFill" in fill
    assert click.startswith("if (!filled)")


def test_rule_is_skipped_without_the_credential_it_requires():
    rules = [
        AutoFillRule(selector="a[id=signInAnotherWay]", action="click", requires="totp")
    ]
    assert get_selectors(rules, Credentials()) == ""
    assert "ocssClick" in get_selectors(rules, Credentials(totp="123456"))


def test_only_visible_elements_are_acted_on():
    script = get_selectors(
        [
            AutoFillRule(selector="input[name=UserName]", fill="username"),
            AutoFillRule(selector="span[id=submitButton]", action="click"),
        ],
        Credentials(),
    )
    # A login page can carry a hidden duplicate of the field it posts; picking
    # `querySelector`'s first match types into that one and reports success.
    assert "document.querySelector(" not in script
    assert script.count("ocssFind(") == 2


def test_stop_rule_requires_a_message_not_just_the_container():
    script = get_selectors(
        [AutoFillRule(selector="span[id=errorText]", action="stop")], Credentials()
    )
    assert "ocssMessage(" in script
    assert "ocssFind(" not in script
