# Managed configuration (organisations)

Administrators can give every KeyMelier installation additional advisory
sources, for example internal findings about key models or firmware used in
the organisation. This is configured only through machine-wide management
(Group Policy / Intune, MDM, configuration management); there is no setting
for it in the app.

**What an additional source can and cannot do**

- It can only **add** findings. The official KeyMelier advisory database
  always stays active; entries with an id that exists in the official
  database are skipped, so a source can neither remove nor weaken nor change
  an official finding.
- Every finding from such a source shows its origin in the app:
  *Source: company policy (Name)*. The status of each source (loaded,
  invalid, not reachable) is listed on a key's *Security* tab under
  *Data freshness*.
- Every source must be signed with the organisation's own Ed25519 key.
  Unsigned, invalid or malformed files are ignored and logged.
- Up to 10 sources; each document at most 2 MB.

## Where KeyMelier reads the configuration

| System | Location | Written by |
|---|---|---|
| Windows | `HKLM\SOFTWARE\Policies\KeyMelier\AdvisorySources\<Name>` | Group Policy, Intune, `.reg` |
| macOS | `/Library/Managed Preferences/com.keymelier.app.plist` | MDM configuration profile |
| Linux | `/etc/keymelier/policy.json` | configuration management |

Only machine-wide locations are read. The user's own registry hive (HKCU)
and user preferences are ignored. On macOS and Linux the file must belong to
root and must not be writable by group or others, otherwise it is ignored.

Each source has three values:

| Value | Meaning |
|---|---|
| `Name` | Shown in the app next to each finding (max. 64 characters). On Windows the name of the registry key. |
| `Location` | `https://` URL or absolute file path of the JSON document. The signature is expected at the same location with `.sig` appended. Plain `http://` is not accepted. |
| `PublicKey` | The source's Ed25519 public key, raw 32 bytes, base64. |

File sources are read at start; URL sources at every update check (at start,
then regularly, and on *Check for updates*). If a source fails later, the last
valid version stays in use; an older document never replaces a newer one.

## 1. Create a key and sign the document

The document has the same format as the official
[`data/advisories.json`](data/advisories.json):

```json
{
  "advisories": [
    {
      "id": "CONTOSO-2026-01",
      "title": "Model X keys from batch 2025/11 must be replaced",
      "note": "Internal finding. Bring the key to the IT service desk.",
      "severity": "HIGH",
      "affected_aaguids": ["00000000-0000-0000-0000-000000000000"],
      "firmware_max_exclusive": "5.7.0",
      "references": ["https://intranet.example.com/keys"]
    }
  ]
}
```

`severity` is one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (other values count
as `MEDIUM`; `CRITICAL` marks the key as critical, all others as a warning).
`firmware_min_inclusive` / `firmware_max_exclusive` are optional. Only
`https://` references are shown.

Sign it with the tool from this repository (Python 3 with `cryptography`):

```sh
python3 tools/advisories_sign.py keygen contoso-signing.pem       # once; prints the public key
KEYMELIER_SIGNING_KEY=contoso-signing.pem \
  python3 tools/advisories_sign.py sign contoso-advisories.json    # sets "updated", writes .sig
python3 tools/advisories_sign.py verify contoso-advisories.json <PublicKey>
```

Keep the private key out of the published location; whoever holds it can add
findings on every managed installation.

## 2. Distribute the configuration

### Windows (`.reg`, Group Policy Preferences or Intune)

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\KeyMelier\AdvisorySources\Contoso IT]
"Location"="https://intranet.example.com/keymelier/contoso-advisories.json"
"PublicKey"="BASE64-PUBLIC-KEY"
```

Both values are `REG_SZ`. A local file works as well, e.g.
`"Location"="C:\\ProgramData\\Contoso\\contoso-advisories.json"`.

### macOS (configuration profile)

Deliver it with your MDM as a custom settings payload for the domain
`com.keymelier.app`, or as a complete profile:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.example.keymelier</string>
  <key>PayloadUUID</key><string>8C0E3E5A-0B6B-4B7E-9E55-1F0B2B5C1A01</string>
  <key>PayloadDisplayName</key><string>KeyMelier advisory sources</string>
  <key>PayloadScope</key><string>System</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.keymelier.app</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>com.example.keymelier.settings</string>
      <key>PayloadUUID</key><string>8C0E3E5A-0B6B-4B7E-9E55-1F0B2B5C1A02</string>
      <key>AdvisorySources</key>
      <array>
        <dict>
          <key>Name</key><string>Contoso IT</string>
          <key>Location</key><string>https://intranet.example.com/keymelier/contoso-advisories.json</string>
          <key>PublicKey</key><string>BASE64-PUBLIC-KEY</string>
        </dict>
      </array>
    </dict>
  </array>
</dict>
</plist>
```

Use your own UUIDs. The installed profile appears as
`/Library/Managed Preferences/com.keymelier.app.plist`.

### Linux

`/etc/keymelier/policy.json`, owned by root, mode `0644`:

```json
{
  "AdvisorySources": [
    {
      "Name": "Contoso IT",
      "Location": "https://intranet.example.com/keymelier/contoso-advisories.json",
      "PublicKey": "BASE64-PUBLIC-KEY"
    }
  ]
}
```

## Checking the result

Start KeyMelier, select a key and open the *Security* tab: under *Data
freshness → Company sources* each source is listed with its state. Why a
source or an entry was skipped is written to the app's log output (start
KeyMelier from a terminal to see it).
