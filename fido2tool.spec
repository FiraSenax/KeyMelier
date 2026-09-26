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
        'cbor2',
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
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
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
            'CFBundleVersion': '1.0.0',
            'CFBundleShortVersionString': '1.0.0',
            'NSHighResolutionCapable': True,
            'NSRequiresAquaSystemAppearance': False,
        },
    )
