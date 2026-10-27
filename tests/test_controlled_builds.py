"""Upgrades must not silently reuse old source, recipe or binary evidence."""
import copy
import json
import shutil
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import build_runtime  # noqa: E402
import build_zxing  # noqa: E402
import license_inputs  # noqa: E402


class ControlledBuildTests(unittest.TestCase):
    def zxing_proof(self):
        sources = build_zxing.inputs()
        return {'recipe_sha256': build_zxing.recipe_hash(), 'wheel_sha256': 'a' * 64,
                'inputs': {s['component']: {'version': s['version'], 'sha256': s['sha256']} for s in sources},
                'vendored_components': next(s['vendored_components'] for s in sources if s['component'] == 'nanobind')}

    def test_zxing_rejects_changed_dependency_recipe_and_vendored_version(self):
        proof = self.zxing_proof()
        build_zxing.validate_proof(proof)
        for mutate in (lambda p: p['inputs']['nanobind'].update(version='999'),
                       lambda p: p['inputs']['zxing-cpp'].update(sha256='f' * 64),
                       lambda p: p.update(recipe_sha256='f' * 64),
                       lambda p: p.update(vendored_components={}),
                       lambda p: p.pop('wheel_sha256')):
            changed = copy.deepcopy(proof)
            mutate(changed)
            with self.assertRaises(ValueError):
                build_zxing.validate_proof(changed)

    def test_installed_wheel_replacement_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'zxingcpp.so'
            binary.write_bytes(b'original compiled module')
            proof = self.zxing_proof()
            proof['installed_binaries'] = {'zxingcpp.so': build_zxing.digest(binary)}
            manifest = Path(tmp) / 'proof.json'
            manifest.write_text(json.dumps(proof))
            from types import SimpleNamespace
            dist = SimpleNamespace(version=proof['inputs']['zxing-cpp']['version'],
                                   files=['zxingcpp.so'], locate_file=lambda _: binary)
            with patch.object(build_zxing, 'PROOF', manifest), patch.object(build_zxing, 'distribution', return_value=dist):
                build_zxing.verify_installed()
                binary.write_bytes(b'a later opaque wheel')
                with self.assertRaisesRegex(ValueError, 'binaries differ'):
                    build_zxing.verify_installed()

    def test_runtime_rejects_new_static_dependency_and_toolchain(self):
        lock = json.loads(build_runtime.LOCK.read_text())
        proof = {'inputs_sha256': build_runtime.digest(build_runtime.LOCK),
                 'recipe_sha256': build_runtime.recipe_hash(), 'sha256': 'a' * 64,
                 'container': lock['container'], 'toolchain_packages': lock['toolchain_packages'],
                 'toolchain_commits': lock['toolchain_commits'],
                 'component_versions': {s['component']: s['version'] for s in lock['sources']
                    if s['component'] in {'zlib', 'zstd', 'mimalloc', 'libfuse', 'squashfuse'}},
                 'linked_files': [{'file': '/usr/lib/' + n, 'sha256': 'b' * 64}
                                  for n in ('libc.a', 'libfuse3.a', 'libsquashfuse.a')]}
        build_runtime.validate_proof(proof)
        for mutate in (lambda p: p['linked_files'].append({'file': '/lib/libunexpected.a', 'sha256': 'b' * 64}),
                       lambda p: p.update(container='alpine:latest'),
                       lambda p: p.update(inputs_sha256='c' * 64),
                       lambda p: p.update(toolchain_commits={}),
                       lambda p: p['component_versions'].update(zlib='0.0.0'),
                       lambda p: p.update(linked_files=[])):
            changed = copy.deepcopy(proof)
            mutate(changed)
            with self.assertRaises(ValueError):
                build_runtime.validate_proof(changed)

    def test_runtime_hash_allows_appimage_digest_but_rejects_code_changes(self):
        data = bytearray(512)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', data, 40, 256)
        struct.pack_into('<HHH', data, 58, 64, 2, 0)
        data[100:113] = b'\0.digest_md5\0'
        struct.pack_into('<QQ', data, 256 + 24, 100, 13)
        struct.pack_into('<I', data, 320, 1)
        struct.pack_into('<QQ', data, 320 + 24, 128, 16)
        before = build_runtime.normalized_hash(data)
        data[128:144] = b'updated digest!!'
        self.assertEqual(before, build_runtime.normalized_hash(data))
        data[200] = 1
        self.assertNotEqual(before, build_runtime.normalized_hash(data))

    def test_source_manifest_tracks_every_locked_sdist(self):
        self.assertEqual(license_inputs.check(), [])
        pins = license_inputs.source_pins()
        self.assertIn('zxing-cpp', pins)
        self.assertIn('nanobind', pins)
        self.assertTrue(all(len(p['sha256']) == 64 for p in pins.values()))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'uv.lock').write_text('[[package]]\nname="new-dependency"\nversion="2.0"\n'
                'sdist={url="https://example.org/library.tar.gz",hash="sha256:' + 'b'*64 + '",size=10}\n')
            self.assertEqual(license_inputs.source_pins(root)['new-dependency']['version'], '2.0')

    def test_upgrade_gate_rejects_stale_overrides_sources_and_notices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / 'packaging', root / 'packaging',
                            ignore=shutil.ignore_patterns('*.png', 'brands', 'windows-msix'))
            shutil.copyfile(ROOT / 'uv.lock', root / 'uv.lock')
            self.assertEqual(license_inputs.check(root), [])
            path = root / 'packaging/license-overrides.json'
            data = json.loads(path.read_text())
            data['fido2']['version'] = '0.0.0'
            path.write_text(json.dumps(data))
            self.assertTrue(any('SPDX override for fido2' in p for p in license_inputs.check(root)))
            path = root / 'packaging/python-sources.json'
            data = json.loads(path.read_text())
            data.pop('certifi')
            path.write_text(json.dumps(data))
            self.assertTrue(any('source manifest is stale' in p for p in license_inputs.check(root)))
            (root / 'packaging/licenses/feather-LICENSE.txt').write_text('truncated notice')
            self.assertTrue(any('Original license text differs' in p for p in license_inputs.check(root)))


if __name__ == '__main__':
    unittest.main()
