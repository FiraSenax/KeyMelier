import sys
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(sys.platform == "darwin", "macOS About panel")
class AboutPanelTests(unittest.TestCase):
    def setUp(self):
        from fido2tool_core import menubar
        self.menubar = menubar
        self.mb = menubar.MenuBar(None, None, Path("x"))

    def credits(self, lang, texts=None):
        with patch.object(self.mb, "_refresh"):
            self.mb.set_language(lang, texts)
        return self.mb.about_credits()

    def links(self, text):
        found = []
        i = 0
        while i < text.length():
            url, rng = text.attribute_atIndex_effectiveRange_("NSLink", i, None)
            if url is not None:
                found.append(str(url.absoluteString()))
            i = rng.location + rng.length
        return found

    def test_page_translations_are_used_and_links_are_fixed(self):
        text = self.credits("ja", {"about.lead": "キーのソムリエ", "about.what": "説明", "about.privacy": "安全",
                                   "about.site": "サイト", "about.source": "ソース", "about.issues": "報告",
                                   "about.evil": "<a href='x'>", "open": "開く"})
        self.assertIn("キーのソムリエ", text.string())
        self.assertNotIn("<a href", text.string(), "unknown keys are ignored")
        self.assertEqual(self.links(text), [u for _, u in self.menubar.ABOUT_LINKS])
        self.assertTrue(all(u.startswith("https://") for u in self.links(text)))

    def test_update_menu_text_is_translated(self):
        with patch.object(self.mb, "_refresh"):
            self.mb.set_language("fr", {"updates": "Rechercher des mises à jour…"})
        self.assertEqual(self.mb._t("updates"), "Rechercher des mises à jour…")
        with patch.object(self.mb, "_refresh"):
            self.mb.set_language("xx")
        self.assertEqual(self.mb._t("updates"), "Check for Updates…")

    def test_missing_texts_fall_back_to_english(self):
        text = self.credits("xx")
        self.assertIn(self.menubar.ABOUT_TEXTS["en"]["about.what"], text.string())

    def test_page_texts_are_plain_text_and_limited(self):
        text = self.credits("fr", {"about.what": "<b>x</b>" * 200})
        self.assertIn("<b>x</b>", text.string())            # shown literally, never parsed as markup
        self.assertLessEqual(len(self.menubar.ABOUT_TEXTS["fr"]["about.what"]), 600)


if __name__ == "__main__":
    unittest.main()
