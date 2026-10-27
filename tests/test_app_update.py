import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from keymelier_core import app_update

PREFIX = app_update.DOWNLOAD_PREFIX + "v9.9.9/"
ASSET = {"name": "KeyMelier-macOS.dmg", "url": PREFIX + "KeyMelier-macOS.dmg", "sums": PREFIX + "SHA256SUMS.txt"}
PAYLOAD = b"disk image bytes" * 1000


def fake_get(sums_digest):
    def get(url, **kwargs):
        resp = MagicMock()
        resp.__enter__.return_value = resp
        resp.headers = {}
        if url.endswith("SHA256SUMS.txt"):
            resp.text = f"{sums_digest}  KeyMelier-macOS.dmg\n{'0' * 64}  KeyMelier-Windows-Setup.exe\n"
            resp.iter_content.side_effect = lambda **kw: [resp.text.encode()]
            return resp
        resp.__enter__.return_value = resp
        resp.headers = {"Content-Length": str(len(PAYLOAD))}
        resp.iter_content.return_value = [PAYLOAD[:5000], PAYLOAD[5000:]]
        return resp
    return get


class AppUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = patch.object(app_update, "_download_dir", return_value=Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_verified_download(self):
        with patch("requests.get", side_effect=fake_get(hashlib.sha256(PAYLOAD).hexdigest())):
            path = app_update.download(ASSET)
        self.assertEqual(path.read_bytes(), PAYLOAD)
        self.assertEqual(path.name, "KeyMelier-macOS.dmg")

    def test_verified_rc_download_and_cross_candidate_checksums(self):
        asset = {key: value.replace('v9.9.9/', 'v9.9.9-rc.3/') for key, value in ASSET.items()}
        with patch('requests.get', side_effect=fake_get(hashlib.sha256(PAYLOAD).hexdigest())):
            self.assertEqual(app_update.download(asset).read_bytes(), PAYLOAD)
        for bad in ('v9.9.9-rc.2', 'v9.9.9', 'v9.9.9-rc.03', 'v9.9.9-beta.1', 'v9.9.9-rc.3%2f..'):
            with self.subTest(bad=bad), patch('requests.get') as get, self.assertRaises(app_update.UpdateError):
                app_update.download({**asset, 'url': asset['url'].replace('v9.9.9-rc.3', bad)})
            get.assert_not_called()

    def test_checksum_mismatch_deletes_file(self):
        with patch("requests.get", side_effect=fake_get("f" * 64)):
            with self.assertRaises(app_update.UpdateError) as e:
                app_update.download(ASSET)
        self.assertEqual(str(e.exception), "checksum")
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])

    def test_only_project_release_urls(self):
        for bad in ({**ASSET, "url": "https://evil.example/KeyMelier-macOS.dmg"},
                    {**ASSET, "sums": "https://github.com/other/repo/releases/download/x/SHA256SUMS.txt"},
                    {**ASSET, "name": "../../evil.dmg"}):
            with self.assertRaises(app_update.UpdateError):
                app_update.download(bad)

    def test_existing_files_and_dangling_symlinks_are_not_overwritten(self):
        directory = Path(self.tmp.name)
        existing = directory / ASSET['name']
        existing.write_bytes(b'keep me')
        with patch("requests.get", side_effect=fake_get(hashlib.sha256(PAYLOAD).hexdigest())):
            result = app_update.download(ASSET)
        self.assertEqual(existing.read_bytes(), b'keep me')
        self.assertEqual(result.read_bytes(), PAYLOAD)
        self.assertNotEqual(result, existing)
        self.assertFalse(list(directory.glob('.keymelier-*.part')))

    def test_predictable_partial_symlink_is_not_followed(self):
        victim = Path(self.tmp.name) / 'important'
        victim.write_bytes(b'private')
        trap = Path(self.tmp.name) / (ASSET['name'] + '.part')
        try:
            trap.symlink_to(victim)
        except OSError:
            self.skipTest('symlinks unavailable')
        with patch("requests.get", side_effect=fake_get(hashlib.sha256(PAYLOAD).hexdigest())):
            app_update.download(ASSET)
        self.assertEqual(victim.read_bytes(), b'private')
        self.assertTrue(trap.is_symlink())

    def test_same_release_and_exact_checksum_filename_required(self):
        with self.assertRaises(app_update.UpdateError):
            app_update.download({**ASSET, 'sums':ASSET['sums'].replace('v9.9.9', 'v8.8.8')})
        get = fake_get(hashlib.sha256(PAYLOAD).hexdigest())
        def misleading(url, **kwargs):
            response = get(url, **kwargs)
            if url.endswith('SHA256SUMS.txt'):
                response.text = response.text.replace('  KeyMelier-macOS.dmg', '  OtherKeyMelier-macOS.dmg')
            return response
        with patch('requests.get', side_effect=misleading), self.assertRaises(app_update.UpdateError):
            app_update.download(ASSET)

    def test_checksum_http_error_is_not_parsed_as_valid_data(self):
        get = fake_get(hashlib.sha256(PAYLOAD).hexdigest())
        def failed(url, **kwargs):
            response = get(url, **kwargs)
            response.raise_for_status.side_effect = OSError('private URL')
            return response
        with patch('requests.get', side_effect=failed), self.assertRaises(app_update.UpdateError):
            app_update.download(ASSET)
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])



class CheckTests(unittest.TestCase):
    """A manual "check for updates" must be able to tell "up to date" from "could not check"."""

    def test_unreachable_is_reported(self):
        with patch("requests.get", side_effect=OSError("offline")):
            result = app_update.check()
        self.assertTrue(result["failed"])
        self.assertFalse(result["newer"])

    def test_no_release_yet_is_not_a_failure(self):
        with patch("requests.get", return_value=self.response(b"", status=404)):
            self.assertFalse(app_update.check()["failed"])

    @staticmethod
    def response(body: bytes, status=200, length=None):
        resp = MagicMock(status_code=status)
        resp.__enter__.return_value = resp
        resp.headers = {} if length is None else {"Content-Length": str(length)}
        resp.iter_content.return_value = [body]
        return resp

    def test_oversized_answer_is_a_failed_check(self):
        with patch("requests.get", return_value=self.response(b"{" + b" " * (2 * 1024 * 1024) + b"}")):
            self.assertTrue(app_update.check()["failed"])

    def test_newer_release(self):
        resp = self.response(json.dumps({"tag_name": "v99.0.0", "html_url": "https://github.com/FiraSenax/KeyMelier/releases/tag/v99.0.0",
                                         "assets": []}).encode())
        with patch("requests.get", return_value=resp):
            result = app_update.check()
        self.assertTrue(result["newer"])
        self.assertFalse(result["failed"])
        self.assertEqual(result["latest"], "99.0.0")

    @staticmethod
    def release(tag, **overrides):
        prefix = app_update.DOWNLOAD_PREFIX + tag + '/'
        return {'tag_name': tag, 'draft': False, 'prerelease': '-rc.' in tag,
                'assets': [{'name': name, 'browser_download_url': prefix + name}
                           for name in ('KeyMelier-macOS.dmg', 'SHA256SUMS.txt')], **overrides}

    def check_releases(self, releases, current='1.8.6', include_rc=True, stable=None):
        def get(url, **kwargs):
            body = releases if url == app_update.RC_RELEASES_API else stable or self.release('v1.8.6')
            return self.response(json.dumps(body).encode())
        with patch('requests.get', side_effect=get) as request, \
             patch.object(app_update, 'current_version', return_value=current), \
             patch.object(app_update.sys, 'platform', 'darwin'):
            result = app_update.check(include_rc=include_rc)
        return result, request

    def test_rcs_require_opt_in_and_numeric_order_not_api_order(self):
        releases = [self.release(tag) for tag in ('v1.8.7-rc.2', 'v1.8.7-rc.10', 'v1.8.7-rc.3')]
        result, request = self.check_releases(releases, include_rc=False)
        self.assertFalse(result['newer'])
        self.assertEqual([c.args[0] for c in request.call_args_list], [app_update.RELEASES_API])
        result, _ = self.check_releases(releases, current='1.8.7-rc.2')
        self.assertEqual(result['latest'], '1.8.7-rc.10')
        self.assertTrue(result['newer'])
        self.assertTrue(result['prerelease'])
        self.assertIn('/v1.8.7-rc.10/', result['asset']['url'])

    def test_final_follows_rc_even_when_outside_the_recent_list(self):
        result, _ = self.check_releases([self.release('v1.8.7-rc.99')], current='1.8.7-rc.99',
                                        stable=self.release('v1.8.7'))
        self.assertEqual(result['latest'], '1.8.7')
        self.assertTrue(result['newer'])
        self.assertFalse(result['prerelease'])

    def test_stable_channel_on_rc_waits_for_final_without_downgrade(self):
        for tag, newer in (('v1.8.6', False), ('v1.8.7', True)):
            result, _ = self.check_releases([], current='1.8.7-rc.3', include_rc=False, stable=self.release(tag))
            self.assertEqual(result['newer'], newer)
        result, _ = self.check_releases([self.release('v1.8.7-rc.3')], current='1.8.7')
        self.assertFalse(result['newer'])

    def test_same_or_older_rc_is_not_offered_again(self):
        for tag in ('v1.8.7-rc.2', 'v1.8.7-rc.3'):
            result, _ = self.check_releases([self.release(tag)], current='1.8.7-rc.3')
            self.assertFalse(result['newer'])

    def test_drafts_other_previews_invalid_tags_and_incomplete_rcs_are_ignored(self):
        releases = [self.release('v99.0.0-rc.1', draft=True), self.release('v99.0.0-beta.1', prerelease=True),
                    self.release('v99.0.0-rc.0'), self.release('v99.0.0-rc.01'),
                    self.release('v99.0.0-rc.1', prerelease=False), self.release('v99.0.0', prerelease=True),
                    self.release('v99.0.0-rc.1', assets=[]), {'tag_name': ['malformed']}, None,
                    self.release('v1.8.7-rc.3')]
        result, _ = self.check_releases(releases)
        self.assertEqual(result['latest'], '1.8.7-rc.3')
        wrong = self.release('v99.0.0-rc.1')
        wrong['assets'][1]['browser_download_url'] = app_update.DOWNLOAD_PREFIX + 'v99.0.0/SHA256SUMS.txt'
        result, _ = self.check_releases([wrong])
        self.assertFalse(result['newer'])

    def test_running_version_uses_the_validated_build_tag(self):
        with patch.object(app_update.build_info, 'load', return_value={'release_tag':'v1.8.7-rc.3'}):
            self.assertEqual(app_update.current_version(), '1.8.7-rc.3')
        with patch.object(app_update.build_info, 'load', return_value={}):
            self.assertEqual(app_update.current_version(), app_update.__version__)

if __name__ == "__main__":
    unittest.main()
