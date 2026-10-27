KeyMelier for Windows
====================

Requires Windows 10/11 (64-bit), Microsoft Visual C++ v14 Redistributable
(x64, version 14.44.35211.0 or later) and Microsoft Edge WebView2 Runtime.

Install the C++ runtime directly from Microsoft before running KeyMelier:
https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
Choose the X64 download and complete Microsoft's installer.

The KeyMelier Setup checks this prerequisite. For the ZIP edition, install
it yourself if required. You can use Microsoft's offline installer on another
computer, subject to Microsoft's terms. KeyMelier does not download it in the
background or accept Microsoft's terms on your behalf.

If WebView2 Runtime is missing, install it directly from Microsoft:
https://developer.microsoft.com/en-us/microsoft-edge/webview2/

The Windows 10/11 system supplies UCRT and Windows API libraries. This package
does not include Microsoft VC, UCRT, MFC or Windows API-set DLLs. The included
WebView2 SDK/loader files have separate BSD-style notices in the license reader.

Licenses and sources
--------------------
About > Licenses & notices shows the complete bundled notices offline, the
KeyMelier MIT license, and the source manifest. You can search and save them.
They are also under _internal/THIRD_PARTY_LICENSES.txt and
_internal/THIRD_PARTY_SOURCES.json. The matching KeyMelier-Sources-Windows.tar
is attached to the same release at:
https://github.com/FiraSenax/KeyMelier/releases

Each component retains its own license. The MIT license covers KeyMelier's
own code. Brand and FIDO metadata usage terms are documented separately in
the notices; no endorsement by their owners is implied.
