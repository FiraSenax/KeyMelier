"""macOS menu bar item: connected keys at a glance.

Shows a template icon in the menu bar. When a key is plugged in, its name and
status appear next to the icon for a few seconds. The menu lists connected
keys (click opens the app on that key), plus "Open KeyMelier" and "Quit".
It also replaces the bare standard "About KeyMelier" panel with one that
says what KeyMelier does, how it treats your data, and where to find more.
All AppKit calls run on the main thread via PyObjCTools.AppHelper.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

FLASH_SECONDS = 5

# Menu texts per UI language (kept short; falls back to English)
TEXTS = {
    "de": {"open": "KeyMelier öffnen", "quit": "Beenden", "none": "Kein Schlüssel verbunden", "updates": "Nach Updates suchen …",
           "UNKNOWN": "unbekannt", "OK": "keine bekannten Hinweise", "WARNING": "Warnung", "CRITICAL": "kritisch", "PENDING": "wird geprüft"},
    "en": {"open": "Open KeyMelier", "quit": "Quit", "none": "No key connected", "updates": "Check for Updates…",
           "UNKNOWN": "unknown", "OK": "no known findings", "WARNING": "warning", "CRITICAL": "critical", "PENDING": "checking"},
}

# "About KeyMelier" panel (the page sends all UI languages via set_language)
ABOUT_TEXTS = {
    "de": {
        "about.lead": "Der Sommelier für deine Sicherheitsschlüssel",
        "about.what": "Prüft FIDO2-Schlüssel auf Echtheit und bekannte Schwachstellen, verwaltet Passkeys, PIN, Codes, OpenPGP und PIV – und zeigt, welche Konten auf welchem Schlüssel liegen.",
        "about.privacy": "Alles bleibt auf diesem Computer: kein Konto, keine Telemetrie.",
        "about.site": "Webseite", "about.source": "Quellcode", "about.issues": "Fehler melden",
    },
    "en": {
        "about.lead": "The sommelier for your security keys",
        "about.what": "Checks FIDO2 keys for authenticity and known vulnerabilities, manages passkeys, PIN, codes, OpenPGP and PIV – and shows which accounts are on which key.",
        "about.privacy": "Everything stays on this computer: no account, no telemetry.",
        "about.site": "Website", "about.source": "Source code", "about.issues": "Report a problem",
    },
}
ABOUT_LINKS = (("about.site", "https://firasenax.github.io/KeyMelier/"),
               ("about.source", "https://github.com/FiraSenax/KeyMelier"),
               ("about.issues", "https://github.com/FiraSenax/KeyMelier/issues"))
COPYRIGHT = "© 2026 Sven Frank · MIT License"

STATUS_MARK = {"UNKNOWN": "○", "OK": "●", "WARNING": "▲", "CRITICAL": "✕", "PENDING": "…"}


class MenuBar:
    def __init__(self, service, window, icon_path: Path):
        self._service = service
        self._window = window
        self._icon_path = icon_path
        self._item = None
        self._target = None
        self._lang = "en"
        self._about_hooked = False
        self._updates_item = None
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

            def showAbout_(self, _sender):
                menubar._show_about()

            def checkUpdates_(self, _sender):
                menubar._check_updates()

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
            about = {k: str(v)[:600] for k, v in texts.items() if k in ABOUT_TEXTS["en"] and isinstance(v, str)}
            if about:
                ABOUT_TEXTS[lang] = about
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

        self._hook_about()
        if self._updates_item is not None:
            self._updates_item.setTitle_(self._t("updates"))
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
        updates_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(self._t("updates"), "checkUpdates:", "")
        updates_item.setTarget_(self._target)
        menu.addItem_(updates_item)
        open_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(self._t("open"), "openApp:", "o")
        open_item.setTarget_(self._target)
        menu.addItem_(open_item)
        quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(self._t("quit"), "quitApp:", "q")
        quit_item.setTarget_(self._target)
        menu.addItem_(quit_item)
        self._item.setMenu_(menu)

    # ── About panel ──────────────────────────────────────────────────────────

    def _about_t(self, key: str) -> str:
        return ABOUT_TEXTS.get(self._lang, {}).get(key) or ABOUT_TEXTS["en"][key]

    def _hook_about(self):
        """Point the app menu's "About KeyMelier" at our panel (once the menu exists)."""
        if self._about_hooked or self._target is None:
            return
        from AppKit import NSApp
        menu = NSApp.mainMenu()
        app_menu = menu.itemAtIndex_(0).submenu() if menu is not None and menu.numberOfItems() else None
        from AppKit import NSMenuItem
        for index, item in enumerate(app_menu.itemArray() if app_menu is not None else []):
            if item.action() == "orderFrontStandardAboutPanel:":
                item.setTarget_(self._target)
                item.setAction_("showAbout:")
                # "Check for Updates…" right below, as in other Mac apps
                self._updates_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                    self._t("updates"), "checkUpdates:", "")
                self._updates_item.setTarget_(self._target)
                app_menu.insertItem_atIndex_(self._updates_item, index + 1)
                self._about_hooked = True
                return

    def about_credits(self):
        """The panel's text: lead, what it does, privacy, links (fits without scrolling)."""
        from AppKit import (NSColor, NSFont, NSFontAttributeName, NSForegroundColorAttributeName,
                            NSLinkAttributeName, NSMutableParagraphStyle, NSParagraphStyleAttributeName)
        from Foundation import NSAttributedString, NSMutableAttributedString, NSURL

        para = NSMutableParagraphStyle.alloc().init()
        para.setAlignment_(1)  # centred, like the rest of the panel
        para.setParagraphSpacing_(6)
        base = {NSFontAttributeName: NSFont.systemFontOfSize_(11), NSParagraphStyleAttributeName: para,
                NSForegroundColorAttributeName: NSColor.labelColor()}
        muted = {**base, NSForegroundColorAttributeName: NSColor.secondaryLabelColor()}
        lead = {**base, NSFontAttributeName: NSFont.boldSystemFontOfSize_(12)}

        text = NSMutableAttributedString.alloc().init()

        def add(s, attrs):
            text.appendAttributedString_(NSAttributedString.alloc().initWithString_attributes_(s, attrs))

        add(self._about_t("about.lead") + "\n", lead)
        add(self._about_t("about.what") + "\n", base)
        add(self._about_t("about.privacy") + "\n", muted)
        for i, (key, url) in enumerate(ABOUT_LINKS):
            if i:
                add(" · ", muted)
            add(self._about_t(key), {**base, NSLinkAttributeName: NSURL.URLWithString_(url)})
        return text

    def _check_updates(self):
        self._open()
        self._window.evaluate_js("window.__kmCheckUpdates && window.__kmCheckUpdates()")

    def _show_about(self):
        from AppKit import NSApp
        from fido2tool_core.version import __version__
        NSApp.activateIgnoringOtherApps_(True)
        NSApp.orderFrontStandardAboutPanelWithOptions_({
            "ApplicationName": "KeyMelier", "ApplicationVersion": __version__, "Version": "",
            "Credits": self.about_credits(), "Copyright": COPYRIGHT,
        })

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
