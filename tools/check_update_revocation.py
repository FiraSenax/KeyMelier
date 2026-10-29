"""Reject accidental revocation of the embedded update key in normal CI.

An intentional emergency stop needs a matching fingerprint and a public reason
in emergency_stop. This acknowledgement never permits release signing with a
revoked key and is not protection against a compromised repository owner.
"""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keymelier_core import update_revocation  # noqa: E402


def check(path: Path, active_fingerprint: str) -> None:
    with path.open('rb') as stream:
        data = stream.read(update_revocation.MAX_BYTES + 1)
    revoked = update_revocation.parse(data)
    acknowledgement = json.loads(data).get('emergency_stop')
    if active_fingerprint not in revoked:
        if acknowledgement is not None:
            raise ValueError('Remove the stale emergency_stop acknowledgement.')
        return
    if not isinstance(acknowledgement, dict) or acknowledgement.get('fingerprint') != active_fingerprint:
        raise ValueError('Active update key is revoked without an explicit emergency_stop acknowledgement.')
    reason = acknowledgement.get('reason')
    if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 1000:
        raise ValueError('The emergency_stop acknowledgement needs a public reason (10–1000 characters).')


if __name__ == '__main__':
    try:
        check(update_revocation.BUNDLED, update_revocation.fingerprint())
    except (OSError, ValueError) as error:
        sys.exit(f'Update revocation policy check failed: {error}')
    print('Update revocation policy checked; no signing authority is granted by this check.')
