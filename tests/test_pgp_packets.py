import base64
import hashlib
import struct
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from fido2tool_core import pgp_packets as P
from fido2tool_core.openpgp_app import _check_user_id
from fido2tool_core.cards import CardError


def parse_packets(data):
    out = []
    i = 0
    while i < len(data):
        tag = data[i] & 0x3F
        first = data[i + 1]
        if first < 192:
            n, i = first, i + 2
        elif first < 224:
            n, i = ((first - 192) << 8) + data[i + 2] + 192, i + 3
        else:
            n, i = struct.unpack(">I", data[i + 2:i + 6])[0], i + 6
        out.append((tag, data[i:i + n]))
        i += n
    return out


class PgpPacketTests(unittest.TestCase):
    def test_encodings(self):
        self.assertEqual(P.mpi(1), b"\x00\x01\x01")
        self.assertEqual(P.mpi(b"\x00\x40\x01"), b"\x00\x0f\x40\x01")
        self.assertEqual(P._crc24(b""), 0xB704CE)
        self.assertEqual(P.packet(13, b"x" * 200)[:3], bytes([0xCD, 192, 8]))

    def test_key_structure_and_signatures(self):
        sk = ed25519.Ed25519PrivateKey.generate()
        digests = []

        def signer(digest):
            digests.append(digest)
            return P.signature_mpis(P.EDDSA, sk.sign(digest))

        created = 1_700_000_000
        primary = P.public_key(sk.public_key(), created)
        enc = P.public_key(x25519.X25519PrivateKey.generate().public_key(), created, encryption=True)
        aut = P.public_key(ed25519.Ed25519PrivateKey.generate().public_key(), created)
        data = P.transferable_key(primary, "Erika <e@example.com>", [(enc, P.FLAG_ENCRYPT), (aut, P.FLAG_AUTH)],
                                  signer, created, 86400)
        tags = [t for t, _ in parse_packets(data)]
        self.assertEqual(tags, [6, 13, 2, 14, 2, 14, 2])
        self.assertEqual(primary.fingerprint, hashlib.sha1(primary.hashed()).digest())
        # ECDH key material: OID, 0x40-prefixed point, KDF params (length 3)
        self.assertTrue(enc.material.endswith(bytes([3, 1, 8, 7])))
        # each signature carries the digest prefix of what the card signed
        sigs = [body for t, body in parse_packets(data) if t == 2]
        for body, digest in zip(sigs, digests):
            hashed_len = struct.unpack(">H", body[4:6])[0]
            unhashed_len = struct.unpack(">H", body[6 + hashed_len:8 + hashed_len])[0]
            self.assertEqual(body[8 + hashed_len + unhashed_len:10 + hashed_len + unhashed_len], digest[:2])
        armored = P.armor(data)
        lines = armored.strip().split("\n")
        payload = base64.b64decode("".join(lines[2:-2]))
        self.assertEqual(payload, data)
        self.assertEqual(lines[-2], "=" + base64.b64encode(struct.pack(">I", P._crc24(data))[1:]).decode())

    def test_user_id_validation(self):
        self.assertEqual(_check_user_id("Erika", "e@example.com"), "Erika <e@example.com>")
        self.assertEqual(_check_user_id("Erika", ""), "Erika")
        for name, email in (("", ""), ("Er<ika", ""), ("Erika", "not-an-email")):
            with self.assertRaises(CardError):
                _check_user_id(name, email)


if __name__ == "__main__":
    unittest.main()
