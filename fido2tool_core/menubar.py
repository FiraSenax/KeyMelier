"""macOS menu bar item: connected keys at a glance.

Shows a template icon in the menu bar. When a key is plugged in, its name and
status appear next to the icon for a few seconds. The menu lists connected
keys (click opens the app on that key), plus "Open KeyMelier" and "Quit".
All AppKit calls run on the main thread via PyObjCTools.AppHelper.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

FLASH_SECONDS = 5

# Menu texts per UI language (kept short; falls back to English)
TEXTS = {
    "de": {"open": "KeyMelier öffnen", "quit": "Beenden", "none": "Kein Schlüssel verbunden",
           "UNKNOWN": "unbekannt", "OK": "keine bekannten Hinweise", "WARNING": "Warnung", "CRITICAL": "kritisch", "PENDING": "wird geprüft"},
    "en": {"open": "Open KeyMelier", "quit": "Quit", "none": "No key connected",
           "UNKNOWN": "unknown", "OK": "no known findings", "WARNING": "warning", "CRITICAL": "critical", "PENDING": "checking"},
}

STATUS_MARK = {"UNKNOWN": "○", "OK": "●", "WARNING": "▲", "CRITICAL": "✕", "PENDING": "…"}


class MenuBar:
    def __init__(self, service, window, icon_path: Path):
        self._service = service
        self._window = window
        self._icon_path = icon_path
        self._item = None
        self._target = None
        self._lang = "en"
        # Kept up to date from the event payloads. Never query the scanner
        # here: its callbacks fire while it holds its own lock.
        self._tokens: dict[str, dict] = {}

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        from PyObjCTools import AppHelper
        AppHelper.callAfter(self._create)

    def _create(self):
        from AppKit import NSImage, NSStatusBar, NSVariableStatusItemLength
        from Foundation import NSObject

        menubar = self

        class _Target(NSObject):
            def openApp_(self, _sender):
                menubar._open()

            def openKey_(self, sender):
                menubar._open(sender.representedObject())

            def quitApp_(self, _sender):
                menubar._quit()

        self._target = _Target.alloc().init()
        self._item = NSStatusBar.systemStatusBar().statusItemWithLength_(NSVariableStatusItemLength)
        image = NSImage.alloc().initWithContentsOfFile_(str(self._icon_path))
        if image is not None:
            image.setSize_((18, 18))
            image.setTemplate_(True)  # follows light/dark menu bar
            self._item.button().setImage_(image)
        else:
            self._item.button().setTitle_("KM")
        self._item.button().setToolTip_("KeyMelier")
        logger.info("Menu bar item created")
        self._rebuild()

    # ── Events from the service ──────────────────────────────────────────────

    def set_language(self, lang: str, texts: dict | None = None):
        """Use the page's own translations when given (all UI languages)."""
        if texts:
            TEXTS[lang] = {k: str(v)[:60] for k, v in texts.items() if k in TEXTS["en"]}
        self._lang = lang if lang in TEXTS else "en"
        self._refresh()

    def on_event(self, name: str, payload: dict):
        if name in ("token_connected", "token_updated"):
            self._tokens[payload["id"]] = payload
        elif name == "token_disconnected":
            self._tokens.pop(payload.get("id"), None)
        else:
            return
        self._refresh()
        if name == "token_connected":
            label = payload.get("mds_description") or payload.get("product_name") or "Key"
            self._flash(label[:28])

    def _refresh(self):
        from PyObjCTools import AppHelper
        AppHelper.callAfter(self._rebuild)

    def _flash(self, text: str):
        from PyObjCTools import AppHelper

        def show():
            if self._item:
                self._item.button().setTitle_(" " + text)

        def clear():
            if self._item:
                self._item.button().setTitle_("")

        AppHelper.callAfter(show)
        AppHelper.callLater(FLASH_SECONDS, clear)

    # ── Menu ─────────────────────────────────────────────────────────────────

    def _t(self, key: str) -> str:
        return TEXTS[self._lang].get(key) or TEXTS["en"][key]

    def _rebuild(self):
        from AppKit import NSMenu, NSMenuItem

        if self._item is None:
            return
        menu = NSMenu.alloc().init()
        menu.setAutoenablesItems_(False)
        if not self._tokens:
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(self._t("none"), None, "")
            item.setEnabled_(False)
            menu.addItem_(item)
        for tok in list(self._tokens.values()):
            status = tok.get("security_status", "PENDING")
            name = tok.get("mds_description") or tok.get("product_name") or "Key"
            title = f"{STATUS_MARK.get(status, '•')}  {name} – {self._t(status)}"
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, "openKey:", "")
            item.setTarget_(self._target)
            item.setRepresentedObject_(tok.get("id"))
            menu.addItem_(item)
        menu.addItem_(NSMenuItem.separatorItem())
        open_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(self._t("open"), "openApp:", "o")
        open_item.setTarget_(self._target)
        menu.addItem_(open_item)
        quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(self._t("quit"), "quitApp:", "q")
        quit_item.setTarget_(self._target)
        menu.addItem_(quit_item)
        self._item.setMenu_(menu)

    def _open(self, token_id=None):
        import json
        from AppKit import NSApp

        try:
            self._window.show()
            self._window.restore()
        except Exception:
            pass
        NSApp.activateIgnoringOtherApps_(True)
        if token_id:
            self._window.evaluate_js(f"window.__kmSelectToken && window.__kmSelectToken({json.dumps(str(token_id))})")

    def _quit(self):
        try:
            self._window.destroy()
        except Exception as e:
            logger.debug("Window destroy failed: %s", e)
