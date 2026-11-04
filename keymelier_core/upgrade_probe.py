"""Isolated 1.8.7 data-upgrade probe, only called by the explicit self-test.

Uses the real history/service/storage code and a synthetic credential store.
No user profile, OS keyring, security key or sync folder is accessed.
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch


def verify_upgrade(fixture: Path) -> bool:
    from keymelier_core import history as history_mod, service as service_mod, storage

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    class Scanner:
        def set_callbacks(self, **callbacks):
            pass

    class CredentialStore:
        locked = False

        def __init__(self):
            self.values = {}

        def get_password(self, service, name):
            if self.locked:
                raise RuntimeError('Synthetic locked credential store')
            return self.values.get((service, name))

        def set_password(self, service, name, value):
            if self.locked:
                raise RuntimeError('Synthetic locked credential store')
            self.values[service, name] = value

    meta = json.loads((fixture / 'keys.json').read_text(encoding='utf-8'))
    require(meta['tag'] == 'v1.8.7' and meta['source_commit'] == '2237689db9f3bbfb33309e6075d819bd9b1d689e',
            'Wrong upgrade fixture provenance')
    with tempfile.TemporaryDirectory(prefix='km-upgrade-probe-') as temp:
        folder = Path(temp)
        for name in ('history.json', 'settings.json'):
            shutil.copyfile(fixture / name, folder / name)
        legacy, encrypted = folder / 'history.json', folder / 'history.encrypted'
        settings_path = folder / 'settings.json'
        settings = json.loads(settings_path.read_text(encoding='utf-8'))
        original = legacy.read_bytes()
        baseline = history_mod.History(legacy, enabled=True, encrypted=False).list()
        require({e['key_id'] for e in baseline} == set(meta['keys'].values()), 'Fixture keys lost')
        store = CredentialStore()

        # Self-test never reaches the host's native credential backend. The real
        # storage.history_cipher still creates, reads and uses its Fernet key.
        with patch.object(storage, '_native_keyring', return_value=store), \
                patch.object(service_mod, 'SETTINGS_FILE', settings_path):
            def start():
                enabled = json.loads(settings_path.read_text(encoding='utf-8'))['history_enabled']
                history = history_mod.History(legacy, enabled=enabled, encrypted=True)
                return service_mod.KeyService(Scanner(), None, history=history)

            svc = start()
            require(svc.history.enabled and svc.history.list() == baseline, 'Migration changed history')
            require(legacy.read_bytes() == original, 'Migration changed plaintext backup')
            cipher = storage.history_cipher(create=False)
            require(cipher.decrypt(encrypted.read_bytes()) == original, 'Encrypted copy differs')
            require(svc.get_settings()['sync_device'] == settings['sync_device'], 'Sync identity changed')
            require(not svc.sync_status()['active'], 'Synthetic profile unexpectedly enabled sync')
            require(start().history.list() == baseline, 'Restart lost migrated history')

            saved = encrypted.read_bytes()
            store.locked = True
            blocked = start()
            require(not blocked.history.enabled and blocked.history.load_problem['code'] == 'history_locked',
                    'Locked store did not block history')
            blocked.set_settings({'history_enabled': True})
            require(encrypted.read_bytes() == saved and legacy.read_bytes() == original,
                    'Locked store changed history files')
            store.locked = False
            svc = start()
            require(svc.history.list() == baseline, 'Unlock did not recover history')

            def cleaned():
                for raw in (legacy.read_bytes(), cipher.decrypt(encrypted.read_bytes())):
                    data = json.loads(raw)
                    require({e['key_id'] for e in data['keys']} == set(meta['keys'].values()), 'Privacy cleanup lost keys')
                    require(next(e for e in data['keys'] if e['key_id'] == meta['keys']['A'])['label'] == 'Everyday key',
                            'Privacy cleanup lost labels')
                    require(all(not e.get(field) for e in data['keys']
                                for field in ('sites', 'inventory', 'sites_probed', 'replace', 'lost_done')),
                            'Privacy cleanup retained contents')
                    require(b'erika' not in raw and b'contoso.example' not in raw, 'Privacy cleanup retained accounts')

            svc.set_settings({'history_enabled': False})
            svc.set_settings({'remember_sites': False})
            cleaned()
            require(not start().history.enabled, 'Restart re-enabled disabled history')
            svc = start()
            svc.set_settings({'history_enabled': True})
            require(svc.history.enabled and not svc.get_settings()['remember_sites'], 'Re-enable lost privacy choice')
            cleaned()

            # A retained old backup must warn on failed cleanup, and a retry
            # must finish without deleting identity or losing other settings.
            legacy.write_bytes(original)
            write = history_mod.atomic_write

            def blocked_backup(path, data):
                if path == legacy:
                    raise PermissionError('Synthetic backup write failure')
                return write(path, data)

            with patch.object(history_mod, 'atomic_write', side_effect=blocked_backup):
                result = svc.set_settings({'remember_sites': False})
            require(any(p['code'] == 'history_privacy_cleanup' for p in result['problems']), 'Cleanup failure was hidden')
            require(legacy.read_bytes() == original, 'Failed cleanup changed original')
            result = svc.set_settings({'remember_sites': False})
            require(not result['problems'], 'Successful retry retained cleanup warning')
            cleaned()
            final = start().get_settings()
            require(all(final.get(k) == v for k, v in settings.items() if k != 'remember_sites'),
                    'Upgrade changed unrelated settings')
            require({p.name for p in folder.iterdir()} == {'history.json', 'history.encrypted', 'settings.json'},
                    'Upgrade left unexpected files')
    return True
