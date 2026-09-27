# dmgbuild settings for KeyMelier-macOS.dmg (see packaging/make-dmg.sh).
# Positions match packaging/dmg-background.svg (760 x 480 points).
import os

app = defines.get("app", "dist/KeyMelier.app")  # noqa: F821 – provided by dmgbuild
here = os.path.abspath("packaging")  # dmgbuild runs this file without __file__; make-dmg.sh runs from the repo root

format = "UDZO"
compression_level = 9
filesystem = "HFS+"
size = None
files = [app]
symlinks = {"Applications": "/Applications"}
icon = os.path.join(here, "..", "static", "icon.icns")  # volume icon

background = os.path.join(here, "dmg-background.png")  # @2x picked up for Retina
# Height includes the title bar (31 pt), so the 480 pt background is fully visible
window_rect = ((200, 120), (760, 511))
default_view = "icon-view"
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
sidebar_width = 0
show_icon_preview = False

icon_size = 128
text_size = 14
arrange_by = None
label_pos = "bottom"
icon_locations = {
    "KeyMelier.app": (190, 236),
    "Applications": (570, 236),
}
