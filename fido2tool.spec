# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file — used by build-mac.command, build-windows.bat and build-linux.sh
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

# Windows file metadata: product name and version are required for signing
WIN_VERSION = None
if sys.platform == 'win32':
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo)
    _v = tuple(int(x) for x in APP_VERSION.split('.')) + (0,)
    WIN_VERSION = VSVersionInfo(
        ffi=FixedFileInfo(filevers=_v, prodvers=_v),
        kids=[
            StringFileInfo([StringTable('040904B0', [
                StringStruct('CompanyName', 'KeyMelier project'),
                StringStruct('FileDescription', 'KeyMelier – security key manager'),
                StringStruct('FileVersion', APP_VERSION),
                StringStruct('InternalName', 'KeyMelier'),
                StringStruct('LegalCopyright', 'MIT License'),
                StringStruct('OriginalFilename', 'KeyMelier.exe'),
                StringStruct('ProductName', 'KeyMelier'),
                StringStruct('ProductVersion', APP_VERSION)])]),
            VarFileInfo([VarStruct('Translation', [0x0409, 1200])]),
        ])

# Linux: Qt web view (PySide6, LGPL) and the Secret Service keyring
LINUX_IMPORTS = [
    'webview.platforms.qt',
    'qtpy',
    'PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets', 'PySide6.QtNetwork',
    'PySide6.QtWebChannel', 'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineWidgets',
    'keyring.backends.SecretService', 'secretstorage', 'jeepney',
] if sys.platform.startswith('linux') else []
# Other Qt bindings qtpy could pick up are never bundled
LINUX_EXCLUDES = ['PyQt5', 'PyQt6', 'PySide2', 'gi'] if sys.platform.startswith('linux') else []

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
    ] + LINUX_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=LINUX_EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Linux: PyInstaller's Qt hooks collect nearly all of Qt (3D, Charts, Multimedia,
# QML modules, …). Keep what Qt WebEngine and its platform plugins link to
# (transitive ldd of QtWebEngineProcess, the Python modules and the kept
# plugins, determined for PySide6 6.11) and Chromium's UI strings for the app's
# 11 languages; the packaged start test proves the result still runs.
if sys.platform.startswith('linux'):
    import re
    QT_KEEP = {'Core', 'DBus', 'EglFSDeviceIntegration', 'Gui', 'Network', 'OpenGL', 'Pdf', 'Positioning',
               'PrintSupport', 'Qml', 'QmlMeta', 'QmlModels', 'QmlWorkerScript', 'Quick', 'QuickWidgets', 'Svg',
               'WaylandClient', 'WaylandEglClientHwIntegration', 'WebChannel', 'WebEngineCore',
               'WebEngineWidgets', 'Widgets', 'WlShellIntegration', 'XcbQpa'}
    # Libraries every desktop provides and that must match its graphics driver,
    # display server, fonts and theme – taken from the system, as the AppImage
    # "excludelist" recommends. Qt's xcb helper libraries (xcb-cursor, …) stay
    # bundled because many desktops lack them.
    HOST_LIBS = (r'lib(asound|dbus-1|fontconfig|freetype|harfbuzz|gbm|drm\w*|GL\w*|EGL|OpenGL|GLX\w*'
                 r'|X11|X11-xcb|xcb|xcb-glx|Xau|Xdmcp|Xext|Xfixes|Xi|Xrender|Xrandr|Xcursor|Xinerama|Xcomposite'
                 r'|Xdamage|Xtst|ICE|SM|gtk-3|gdk-3|gdk_pixbuf-2\.0|atk-1\.0|atk-bridge-2\.0|atspi|pango\w*-1\.0'
                 r'|cairo|cairo-gobject|pixman-1|epoxy|glib-2\.0|gobject-2\.0|gio-2\.0|gmodule-2\.0|udev|systemd'
                 r'|cups|avahi-\w+|gcc_s|stdc\+\+|selinux|mount|blkid|wayland-\w+)\.so(\.[0-9.]+)?')
    QT_LOCALES = {'de', 'en-US', 'en-GB', 'es', 'fr', 'it', 'ja', 'ko', 'nl', 'pl', 'pt-BR', 'pt-PT', 'zh-CN', 'zh-TW'}

    def _wanted(dest):
        dest = dest.replace('\\', '/')
        lib = re.search(r'libQt6([A-Za-z0-9]+)\.so', dest) or re.search(r'PySide6/Qt([A-Za-z0-9]+)\.abi3\.so', dest)
        if lib and lib.group(1) not in QT_KEEP:
            return False
        if '/Qt/qml/' in dest or 'virtualkeyboard' in dest.lower() or 'FFmpeg' in dest:
            return False
        if re.search(r'/Qt/plugins/(position|qmltooling|generic|egldeviceintegrations|multimedia)/', dest):
            return False
        if re.search(r'(^|/)lib(avcodec|avformat|avutil|swresample|swscale)\.so', dest):
            return False
        if re.fullmatch(HOST_LIBS, dest.rsplit('/', 1)[-1]):
            return False
        locale = re.search(r'/qtwebengine_locales/([^/]+)\.pak$', dest)
        return not locale or locale.group(1) in QT_LOCALES

    a.binaries = [entry for entry in a.binaries if _wanted(entry[0])]
    a.datas = [entry for entry in a.datas if _wanted(entry[0])]

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
    version=WIN_VERSION,
    uac_admin=sys.platform == 'win32',  # FIDO access on Windows needs administrator rights
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
