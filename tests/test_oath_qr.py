"""Exercise the actual image decoder and ensure previews cannot write a key."""
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from PIL import Image
import zxingcpp

from keymelier_core import oath_qr, oath_app
from keymelier_core.pin import PinError

URI = 'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60'


def qr_image(uri=URI):
    return Image.fromarray(zxingcpp.create_barcode(uri, zxingcpp.BarcodeFormat.QRCode).to_image(scale=5)).convert('RGB')


def encoded(image, kind='PNG'):
    stream = io.BytesIO()
    image.save(stream, format=kind)
    return stream.getvalue()


class OathQrTests(unittest.TestCase):
    def test_png_and_jpeg_preserve_all_credential_parameters(self):
        for kind in ('PNG', 'JPEG'):
            with self.subTest(kind=kind):
                data = oath_qr.decode_image(encoded(qr_image(), kind))
                self.assertEqual(data, dict(issuer='Example', name='alice', secret='JBSWY3DPEHPK3PXP',
                    oath_type='TOTP', algorithm='SHA256', digits=8, period=60, counter=0))

    def test_hotp_counter_reaches_the_device_without_resetting_to_zero(self):
        data = oath_qr.parse_uri(URI.replace('totp', 'hotp').replace('period=60', 'counter=123456'))
        session = Mock()
        session.list_credentials.return_value = []
        with patch.object(oath_app, '_session', return_value=session), patch.object(oath_app, '_account', return_value={}):
            oath_app.add(object(), **data)
        sent = session.put_credential.call_args.args[0]
        self.assertEqual((sent.counter, sent.hash_algorithm.name, sent.digits), (123456, 'SHA256', 8))

    def test_invalid_images_and_missing_codes_have_sanitized_errors(self):
        for raw, code in [(b'private-file-name-and-secret', 'qr_image'),
                          (encoded(Image.new('RGB', (200, 200), 'white')), 'qr_no_code'),
                          (encoded(qr_image('https://example.com/private')), 'qr_no_code')]:
            with self.subTest(code=code), self.assertRaises(PinError) as cm:
                oath_qr.decode_image(raw)
            self.assertEqual(cm.exception.code, code)
            self.assertNotIn('private', str(cm.exception))

    def test_multiple_accounts_are_not_silently_selected(self):
        first, second = qr_image(), qr_image(URI.replace('alice', 'bob'))
        canvas = Image.new('RGB', (first.width + second.width + 100, max(first.height, second.height)), 'white')
        canvas.paste(first, (0, 0))
        canvas.paste(second, (first.width + 100, 0))
        with self.assertRaises(PinError) as cm:
            oath_qr.decode_image(encoded(canvas))
        self.assertEqual(cm.exception.code, 'qr_multiple')

    def test_limits_before_image_decoding(self):
        with patch.object(oath_qr, 'MAX_IMAGE_BYTES', 10):
            with self.assertRaises(PinError) as cm:
                oath_qr.decode_image(b'x' * 11)
        self.assertEqual(cm.exception.code, 'qr_large')
        with patch.object(oath_qr, 'MAX_IMAGE_PIXELS', 100):
            with self.assertRaises(PinError) as cm:
                oath_qr.decode_image(encoded(qr_image()))
        self.assertEqual(cm.exception.code, 'qr_large')

    def test_ambiguous_unsupported_and_malformed_uris_are_rejected(self):
        for uri in [URI+'&secret=SECOND', URI+'&issuer=Other', URI.replace('issuer=Example','issuer=Other'),
                    URI.replace('SHA256','MD5'), URI.replace('digits=8','digits=10'),
                    URI.replace('period=60','period=0'), URI.replace('alice','%00private'),
                    URI.replace('JBSWY3DPEHPK3PXP','!bad'), URI.replace('alice',''),
                    URI.replace('totp','hotp'), URI+'&counter=1', URI+'&unknown=true',
                    URI.replace('totp','hotp').replace('period=60','counter=-1'),
                    URI.replace('totp','hotp').replace('period=60','counter=4294967296'),
                    'otpauth-migration://offline?data=private', 'https://example.com/private']:
            with self.subTest(uri=uri), self.assertRaises(PinError) as cm:
                oath_qr.parse_uri(uri)
            self.assertEqual(cm.exception.code, 'qr_invalid')
            self.assertNotIn('JBSWY', str(cm.exception))

    def test_native_dialog_cancel_preview_and_no_device_access(self):
        import app
        service = Mock()
        api = app.Api(service)
        api._window = Mock()
        api._window.create_file_dialog.return_value = None
        self.assertEqual(api.read_oath_qr(), {'ok': True, 'data': None})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'private.png'
            raw = encoded(qr_image())
            path.write_bytes(raw)
            api._window.create_file_dialog.return_value = (str(path),)
            self.assertEqual(api.read_oath_qr()['data']['name'], 'alice')
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(list(Path(tmp).iterdir()), [path])
        self.assertEqual(service.mock_calls, [])

