import asyncio
import json
import logging
import multiprocessing
import signal
import sys
from urllib.parse import urlparse

import attr

try:
    from importlib.resources import files
except ImportError:
    # Fallback for Python < 3.9
    import pkg_resources

    def files(package):
        class FilePath:
            def __init__(self, pkg, path):
                self.pkg = pkg
                self.path = path

            def __truediv__(self, other):
                return FilePath(self.pkg, self.path + "/" + other)

            def read_text(self):
                return pkg_resources.resource_string(self.pkg, self.path).decode(
                    "utf-8"
                )

        return FilePath(package, "")


import structlog

from PyQt6.QtCore import QUrl, QTimer, pyqtSlot, Qt
from PyQt6.QtNetwork import QNetworkCookie, QNetworkProxy
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile,
    QWebEngineScript,
    QWebEngineSettings,
    QWebEnginePage,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QApplication, QWidget, QSizePolicy, QVBoxLayout

from openconnect_sso import config


app = None
profile = None
logger = structlog.get_logger("webengine")


@attr.s
class Url:
    url = attr.ib()


@attr.s
class Credentials:
    credentials = attr.ib()


@attr.s
class StartupInfo:
    url = attr.ib()
    credentials = attr.ib()


@attr.s
class SetCookie:
    name = attr.ib()
    value = attr.ib()


class Process(multiprocessing.Process):
    def __init__(self, proxy, display_mode):
        super().__init__()

        self._commands = multiprocessing.Queue()
        self._states = multiprocessing.Queue()
        self.proxy = proxy
        self.display_mode = display_mode
        # Depending on the start method the child may be a fresh interpreter
        # that never ran the parent's logging setup, which would silently drop
        # every message the browser produces -- including the ones explaining
        # why auto-login did not fill a field.
        self.log_level = logging.getLogger().level

    def authenticate_at(self, url, credentials):
        self._commands.put(StartupInfo(url, credentials))

    async def get_state_async(self):
        while self.is_alive():
            try:
                return self._states.get_nowait()
            except multiprocessing.queues.Empty:
                await asyncio.sleep(0.01)
        if not self.is_alive():
            raise EOFError()

    def run(self):
        # To work around funky GC conflicts with C++ code by ensuring QApplication terminates last
        global app
        global profile

        signal.signal(signal.SIGTERM, on_sigterm)
        signal.signal(signal.SIGINT, signal.SIG_DFL)

        from openconnect_sso.app import configure_logger

        configure_logger(logging.getLogger(), self.log_level)

        cfg = config.load()

        argv = sys.argv.copy()
        if self.display_mode == config.DisplayMode.HIDDEN:
            argv += ["-platform", "minimal"]
        else:
            # Add platform-specific Qt arguments for better X11/Wayland compatibility
            import os

            # Set Qt platform plugin based on environment if not already set
            if not os.environ.get("QT_QPA_PLATFORM"):
                # For X11 environments, ensure we use the xcb platform
                if os.environ.get("DISPLAY"):
                    os.environ["QT_QPA_PLATFORM"] = "xcb"
                # For Wayland environments with fallback to X11
                elif os.environ.get("WAYLAND_DISPLAY"):
                    # Try Wayland first, but Qt will fallback to xcb if needed
                    if not os.environ.get("QT_QPA_PLATFORM"):
                        os.environ["QT_QPA_PLATFORM"] = "wayland;xcb"

            # Set Qt scale factor mode for better high-DPI support
            if not os.environ.get("QT_SCALE_FACTOR_ROUNDING_POLICY"):
                os.environ["QT_SCALE_FACTOR_ROUNDING_POLICY"] = "PassThrough"

        app = QApplication(argv)

        profile = QWebEngineProfile("openconnect-sso")

        # Configure WebEngine settings for better compatibility
        try:
            # Disable hardware acceleration if GLX issues occur
            settings = profile.settings()
            settings.setAttribute(
                QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, False
            )
            settings.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, False)
        except Exception as e:
            logger.warning("Failed to configure WebEngine settings", error=str(e))

        if self.proxy:
            parsed = urlparse(self.proxy)
            if parsed.scheme.startswith("socks5"):
                proxy_type = QNetworkProxy.ProxyType.Socks5Proxy
            elif parsed.scheme.startswith("http"):
                proxy_type = QNetworkProxy.ProxyType.HttpProxy
            else:
                raise ValueError("Unsupported proxy type", parsed.scheme)
            proxy = QNetworkProxy(proxy_type, parsed.hostname, parsed.port)

            QNetworkProxy.setApplicationProxy(proxy)

        # In order to make Python able to handle signals
        force_python_execution = QTimer()
        force_python_execution.start(200)

        def ignore():
            pass

        force_python_execution.timeout.connect(ignore)
        web = WebBrowser(cfg.auto_fill_rules, self._states.put, profile)

        startup_info = self._commands.get()
        logger.info("Browser started", startup_info=startup_info)

        logger.info("Loading page", url=startup_info.url)

        web.authenticate_at(QUrl(startup_info.url), startup_info.credentials)

        web.show()
        rc = app.exec()

        logger.info("Exiting browser")
        return rc

    async def wait(self):
        while self.is_alive():
            await asyncio.sleep(0.01)
        self.join()


def on_sigterm(signum, frame):
    logger.info("Terminate requested.")
    # Force flush cookieStore to disk. Without this hack the cookieStore may
    # not be synced at all if the browser lives only for a short amount of
    # time. Something is off with the call order of destructors as there is no
    # such issue in C++.

    # See: https://github.com/qutebrowser/qutebrowser/commit/8d55d093f29008b268569cdec28b700a8c42d761
    cookie = QNetworkCookie()
    profile.cookieStore().deleteCookie(cookie)

    # Give some time to actually save cookies
    exit_timer = QTimer(app)
    exit_timer.timeout.connect(QApplication.quit)
    exit_timer.start(1000)  # ms


class WebPage(QWebEnginePage):
    """A page that forwards what the auto-fill script reports to our log."""

    def javaScriptConsoleMessage(self, level, message, line, source):
        if message.startswith("openconnect-sso:"):
            logger.info("Auto-fill", message=message[len("openconnect-sso:") :].strip())
        else:
            logger.debug("Console message", message=message, line=line, source=source)


class WebBrowser(QWebEngineView):
    def __init__(self, auto_fill_rules, on_update, profile):
        super().__init__()
        self._on_update = on_update
        self._auto_fill_rules = auto_fill_rules
        page = WebPage(profile, self)
        self.setPage(page)
        cookie_store = self.page().profile().cookieStore()
        cookie_store.cookieAdded.connect(self._on_cookie_added)
        self.page().loadFinished.connect(self._on_load_finished)

    def createWindow(self, type):
        if type == QWebEnginePage.WebWindowType.WebDialog:
            self._popupWindow = WebPopupWindow(self.page().profile())
            return self._popupWindow.view()

    def authenticate_at(self, url, credentials):
        script_source = (files(__package__) / "user.js").read_text()
        script = QWebEngineScript()
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.ApplicationWorld)
        script.setSourceCode(script_source)
        self.page().scripts().insert(script)

        if credentials:
            logger.info("Initiating autologin", cred=credentials)
            for url_pattern, rules in self._auto_fill_rules.items():
                script = QWebEngineScript()
                script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
                script.setWorldId(QWebEngineScript.ScriptWorldId.ApplicationWorld)
                script.setSourceCode(
                    f"""
// ==UserScript==
// @include {url_pattern}
// ==/UserScript==

{AUTO_FILL_HELPERS}

function autoFill() {{
    var filled = false;
    {get_selectors(rules, credentials)}
    setTimeout(autoFill, 1000);
}}
autoFill();
"""
                )
                self.page().scripts().insert(script)

        self.load(QUrl(url))

    def _on_cookie_added(self, cookie):
        logger.debug("Cookie set", name=to_str(cookie.name()))
        self._on_update(SetCookie(to_str(cookie.name()), to_str(cookie.value())))

    def _on_load_finished(self, success):
        url = self.page().url().toString()
        logger.debug("Page loaded", url=url)

        self._on_update(Url(url))


class WebPopupWindow(QWidget):
    def __init__(self, profile):
        super().__init__()
        self._view = QWebEngineView(self)

        super().setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        super().setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)

        layout = QVBoxLayout()
        super().setLayout(layout)
        layout.addWidget(self._view)

        self._view.setPage(QWebEnginePage(profile, self._view))

        self._view.titleChanged.connect(super().setWindowTitle)
        self._view.page().geometryChangeRequested.connect(
            self.handleGeometryChangeRequested
        )
        self._view.page().windowCloseRequested.connect(super().close)

    def view(self):
        return self._view

    @pyqtSlot("const QRect")
    def handleGeometryChangeRequested(self, newGeometry):
        self._view.setMinimumSize(newGeometry.width(), newGeometry.height())
        super().move(newGeometry.topLeft() - self._view.pos())
        super().resize(0, 0)
        super().show()


def to_str(qval):
    return bytes(qval).decode()


# Modern identity providers (Entra ID among them) render their login forms with
# frameworks that track input values internally, so assigning to `elem.value`
# is silently ignored on submit. Going through the native property setter
# bypasses that tracking, and the bubbling `input`/`change` events afterwards
# make the framework pick the new value up.
AUTO_FILL_HELPERS = """
// Login pages routinely carry several elements matching the same selector: a
// visible field plus a hidden one that the form actually posts, or an error
// container that is rendered empty until there is something to say. Acting on
// `querySelector`'s first match therefore types into the wrong element and
// reports success. Only elements that are laid out and visible count.
function ocssFind(selector) {
    var candidates = document.querySelectorAll(selector);
    for (var i = 0; i < candidates.length; i++) {
        var elem = candidates[i];
        if (elem.disabled || elem.getClientRects().length === 0) {
            continue;
        }
        if (window.getComputedStyle(elem).visibility === "hidden") {
            continue;
        }
        return elem;
    }
    return null;
}

// `stop` rules guard against hammering an identity provider with a password it
// has already rejected, so they have to trigger on an error actually being
// shown -- AD FS keeps an empty error container in the DOM at all times.
function ocssMessage(selector) {
    var candidates = document.querySelectorAll(selector);
    for (var i = 0; i < candidates.length; i++) {
        if (candidates[i].textContent.trim().length > 0) {
            return candidates[i];
        }
    }
    return null;
}

function ocssFill(elem, name, value) {
    if (elem.readOnly || elem.value === value) {
        return false;
    }
    console.log("openconnect-sso: filling " + name);
    var setter = Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(elem), "value"
    );
    elem.focus();
    if (setter && setter.set) {
        setter.set.call(elem, value);
    } else {
        elem.value = value;
    }
    elem.dispatchEvent(new Event("input", { bubbles: true }));
    elem.dispatchEvent(new Event("change", { bubbles: true }));
    elem.dispatchEvent(new Event("blur"));
    return true;
}

function ocssClick(elem, name) {
    console.log("openconnect-sso: clicking " + name);
    elem.focus();
    elem.click();
    return true;
}
"""


def get_selectors(rules, credentials):
    statements = []
    for rule in rules:
        selector = json.dumps(rule.selector)
        if rule.requires and not getattr(credentials, rule.requires, None):
            logger.debug(
                "Skipping rule, required credential not available",
                selector=rule.selector,
                requires=rule.requires,
            )
            continue
        if rule.action == "stop":
            statements.append(
                f"""var elem = ocssMessage({selector}); if (elem) {{ console.log("openconnect-sso: stopping at " + {selector}); return; }}"""
            )
        elif rule.fill:
            credential = getattr(credentials, rule.fill, None)
            if credential:
                value = json.dumps(credential)
                statements.append(
                    f"""var elem = ocssFind({selector}); if (elem) {{ filled = ocssFill(elem, {selector}, {value}) || filled; }}"""
                )
            else:
                logger.warning(
                    "Credential info not available",
                    type=rule.fill,
                    possibilities=dir(credentials),
                )
        elif rule.action == "click":
            # Only submit once nothing was typed in this pass: a form filled
            # and submitted within the same tick tends to be submitted before
            # the page has processed the new value.
            statements.append(
                f"""if (!filled) {{ var elem = ocssFind({selector}); if (elem) {{ ocssClick(elem, {selector}); }} }}"""
            )
    return "\n".join(statements)
