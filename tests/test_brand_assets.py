"""Reviewed brand assets must be deliverable through the UI's link policy."""
import ast
import json
import unittest
from pathlib import Path
from urllib.parse import urlparse

from tools import make_service_icons

ROOT = Path(__file__).resolve().parent.parent


class BrandAssetTests(unittest.TestCase):
    def test_generated_icons_and_every_link_host(self):
        text = (ROOT / "static/service-icons.js").read_text()
        self.assertEqual(text, make_service_icons.render())
        icons = json.loads(text.split("const SERVICE_ICONS = ", 1)[1].strip().removesuffix(";"))
        tree = ast.parse((ROOT / "app.py").read_text())
        allowed = next(ast.literal_eval(node.value) for node in tree.body
                       if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "ALLOWED_LINK_HOSTS"
                               for target in node.targets))
        for name, icon in icons.items():
            with self.subTest(brand=name):
                self.assertEqual(urlparse(icon["url"]).scheme, "https")
                self.assertIn(urlparse(icon["url"]).hostname, allowed)

    def test_no_unreviewed_or_orphaned_svg(self):
        brands = make_service_icons.reviewed_brands()
        for path in make_service_icons.BRANDS.glob("*.svg"):
            with self.subTest(asset=path.name):
                self.assertIn(path.stem, brands)
                entry = brands[path.stem]
                self.assertIn(entry["status"], ("enabled", "rejected"))
                if entry["status"] == "enabled":
                    self.assertEqual(entry["asset"], path.name)
                    self.assertTrue(make_service_icons.asset_bytes(path.stem, entry))
        self.assertFalse((make_service_icons.BRANDS / "netlify.svg").exists())

