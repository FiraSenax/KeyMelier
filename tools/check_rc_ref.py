#!/usr/bin/env python3
"""RC tags select signed artifact builds, never public releases."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fido2tool_core.version import __version__  # noqa: E402


def validate(tag: str, version: str = __version__) -> int:
    match = re.fullmatch(r'v' + re.escape(version) + r'-rc\.([1-9][0-9]*)', tag)
    if not match:
        raise ValueError(f'RC tag must be v{version}-rc.N (positive candidate number)')
    return int(match[1])


if __name__ == '__main__':
    try:
        validate(sys.argv[1])
    except (IndexError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print('RC tag matches the packaged version; artifact-only build')
