# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file — used by both build-mac.command and build-windows.bat
# Run: pyinstaller fido2tool.spec
#
# Icon injection: set KEYMELIER_ICON env var to an .icns (macOS) or .ico
# (Windows) path before running. CI generates these from icon.svg automatically.

import os
import sys
from pathlib import Path

block_cipher = None

# App version for the bundle metadata
_version_ns = {}
exec(Path('fido2tool_core/version.py').read_text(), _version_ns)
APP_VERSION = _version_ns['__version__']

# Licenses of everything bundled on this platform (MIT/BSD need their notices
# in binary distributions; LGPL/MPL their source locations)
sys.path.insert(0, str(Path('tools').resolve()))
import third_party_licenses  # noqa: E402
LICENSES_FILE = third_party_licenses.write(Path('build') / 'THIRD_PARTY_LICENSES.txt')
import sbom  # noqa: E402
SBOM_FILE = sbom.write(Path('build') / 'keymelier-sbom.cdx.json', APP_VERSION)

# Icon path can be overridden via env var (used by CI)
icon_path = os.environ.get('KEYMELIER_ICON') or None

a = Analysis(
    ['app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('static',        'static'),
        ('data',          'data'),
        ('fido2tool_core','fido2tool_core'),
        (str(LICENSES_FILE), '.'),
        (str(SBOM_FILE), '.'),
        ('LICENSE', '.'),
    ],
    hiddenimports=[
        # fido2 / CTAP
        'fido2',
        'fido2.hid',
        'fido2.ctap2',
        'fido2.ctap2.base',
        'fido2.ctap2.extensions',
        'fido2.ctap2.pin',
        'fido2.webauthn',
        'fido2.cbor',
        'fido2.ctap2.credman',
        'fido2.ctap2.bio',
        # YubiKey serial/firmware/form factor via the management application
        'yubikit.management',
        'yubikit.core.fido',
        # Smart card applications (OATH, OpenPGP) over PC/SC
        'yubikit.core.smartcard',
        'yubikit.oath',
        'yubikit.openpgp',
        'ykman.pcsc',
        'yubikit.piv',
        'yubikit.yubiotp',
        'yubikit.management',
        'yubikit.core.otp',
        'ykman.piv',
        'ykman.scancodes',
        'ykman.hid',
        'ykman.hid.base',
        'ykman.hid.macos',
        'ykman.hid.windows',
        'ykman.hid.linux',
        'smartcard',
        'smartcard.System',
        'smartcard.pcsc',
        'smartcard.pcsc.PCSCReader',
        'smartcard.pcsc.PCSCContext',
        'smartcard.CardConnection',
        'smartcard.ExclusiveConnectCardConnection',
        # Native window
        'webview',
        # Cryptography
        'cryptography',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.asymmetric.padding',
        'cryptography.hazmat.backends.openssl',
        # stdlib extras picked up at runtime
        'OpenSSL.crypto',
        'requests',
        'base64',
        'uuid',
        'hashlib',
        'struct',
        'threading',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='KeyMelier',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=os.environ.get("KEYMELIER_SIGN_IDENTITY"),
    entitlements_file="data/macos-entitlements.plist" if os.environ.get("KEYMELIER_SIGN_IDENTITY") else None,
    icon=icon_path,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='KeyMelier',
)

# macOS .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='KeyMelier.app',
        icon=icon_path,
        bundle_identifier='com.keymelier.app',
        info_plist={
            'CFBundleName': 'KeyMelier',
            'CFBundleDisplayName': 'KeyMelier',
            'CFBundleVersion': APP_VERSION,
            'CFBundleShortVersionString': APP_VERSION,
            'NSHighResolutionCapable': True,
            'NSRequiresAquaSystemAppearance': False,
        },
    )
