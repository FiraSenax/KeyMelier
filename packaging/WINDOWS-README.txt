KeyMelier for Windows
====================

Requires Windows 10/11 (64-bit), Microsoft Visual C++ v14 Redistributable
(x64, version 14.44.35211.0 or later) and Microsoft Edge WebView2 Runtime.

Install the C++ runtime directly from Microsoft before running KeyMelier:
https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
Choose the X64 download and complete Microsoft's installer.

KeyMelier Setup checks this prerequisite and skips the extra step if a suitable
runtime is already installed. Otherwise it asks before downloading Microsoft's
official x64 installer, checks its Microsoft signature and opens its normal UI.
Complete Microsoft's setup to return automatically to KeyMelier installation.
You can decline or cancel; KeyMelier is not installed until the prerequisite is
available. A required reboot is reported and never forced by the runtime helper.
For the ZIP edition or silent deployment, install it separately if required.
You can use Microsoft's offline installer on another computer, subject to
Microsoft's terms. KeyMelier never accepts those terms on your behalf.

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
