"""Operation-scoped management tokens; synthetic devices and PINs only."""
import threading
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV1

from keymelier_core import auth, service
from keymelier_core.bridge import dispatch
from keymelier_core.operations import PendingOperations

P = ClientPin.PERMISSION
FULL = P.CREDENTIAL_MGMT | P.BIO_ENROLL | P.AUTHENTICATOR_CFG
SCOPES = {"passkeys": P.CREDENTIAL_MGMT, "fingerprints": P.BIO_ENROLL,
          "settings": P.AUTHENTICATOR_CFG, "read": P.CREDENTIAL_MGMT}


class ScopedUnlockTests(unittest.TestCase):
    def setUp(self):
        self.key = "scoped-synthetic-key"
        auth.forget(self.key, disconnected=True)
        self.addCleanup(auth.forget, self.key, disconnected=True)
        self.ctap = SimpleNamespace(info=SimpleNamespace(options={
            "clientPin": True, "uv": True, "pinUvAuthToken": True,
            "credMgmt": True, "bioEnroll": True, "authnrCfg": True},
            pin_uv_protocols=[1], versions=["FIDO_2_1"]))

    def test_pin_and_uv_request_only_selected_permission(self):
        for uv in (False, True):
            for scope, need in SCOPES.items():
                with self.subTest(uv=uv, scope=scope):
                    auth.forget(self.key, disconnected=True)
                    method = "get_uv_token" if uv else "get_pin_token"
                    cancel = threading.Event()
                    with patch.object(ClientPin, method, return_value=b"synthetic-token") as request:
                        auth.unlock(self.key, self.ctap, pin="synthetic-pin", use_uv=uv,
                                    scope=scope, cancel=cancel)
                    self.assertEqual(request.call_count, 1)
                    self.assertEqual(request.call_args.kwargs["permissions"], need)
                    self.assertNotIn("permissions_rpid", request.call_args.kwargs)
                    if uv:
                        self.assertIs(request.call_args.kwargs["event"], cancel)
                    self.assertEqual(auth.get_token(self.key, need)[1], b"synthetic-token")
                    for other in (P.CREDENTIAL_MGMT, P.BIO_ENROLL, P.AUTHENTICATOR_CFG):
                        self.assertEqual(auth.is_unlocked(self.key, other), other == need)

    def test_new_scope_replaces_token_instead_of_combining_permissions(self):
        with patch.object(ClientPin, "get_pin_token", return_value=b"synthetic-token"):
            auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope="passkeys")
            auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope="settings")
        self.assertTrue(auth.is_unlocked(self.key, P.AUTHENTICATOR_CFG))
        self.assertFalse(auth.is_unlocked(self.key, P.CREDENTIAL_MGMT))
        with self.assertRaises(auth.AuthError) as caught:
            auth.get_token(self.key, P.CREDENTIAL_MGMT)
        self.assertEqual(caught.exception.code, "locked")

    def test_invalid_or_unsupported_scope_never_submits_a_pin(self):
        for scope in ("arbitrary", "", [], 1, True):
            with self.subTest(scope=scope), patch.object(ClientPin, "get_pin_token") as request:
                with self.assertRaises(auth.AuthError) as caught:
                    auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope=scope)
                self.assertEqual(caught.exception.code, "invalid_input")
                request.assert_not_called()
                # Service validation must happen before queuing/device access.
                scanner = Mock()
                svc = object.__new__(service.KeyService)
                svc._scanner = scanner
                with self.assertRaises(auth.AuthError):
                    svc.unlock(self.key, pin="synthetic-pin", scope=scope)
                scanner.session.assert_not_called()
        self.ctap.info.options.pop("bioEnroll")
        with patch.object(ClientPin, "get_pin_token") as request:
            with self.assertRaises(auth.AuthError) as caught:
                auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope="fingerprints")
            self.assertEqual(caught.exception.code, "unsupported")
            request.assert_not_called()

    def test_read_fallback_keeps_bio_and_config_only_keys_accessible(self):
        self.ctap.info.options["credMgmt"] = False
        for option, need in (("bioEnroll", P.BIO_ENROLL), ("authnrCfg", P.AUTHENTICATOR_CFG)):
            with self.subTest(option=option), patch.object(ClientPin, "get_pin_token", return_value=b"t") as request:
                auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope="read")
                self.assertEqual(request.call_args.kwargs["permissions"], need)
            self.ctap.info.options.pop(option)

    def test_wrong_pin_is_sent_once_and_not_cached(self):
        with patch.object(ClientPin, "get_pin_token", side_effect=CtapError(CtapError.ERR.PIN_INVALID)) as request, \
                patch.object(ClientPin, "get_pin_retries", return_value=(7, False)):
            with self.assertRaises(auth.AuthError) as caught:
                auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope="settings")
        request.assert_called_once()
        self.assertEqual(caught.exception.code, "pin_invalid")
        self.assertEqual(caught.exception.extra["retries"], 7)
        self.assertFalse(auth.is_unlocked(self.key))
        self.assertNotIn(self.key, auth._pending)

    def test_scoped_uv_refusal_does_not_retry_or_disable_other_scopes(self):
        with patch.object(ClientPin, "get_uv_token", side_effect=CtapError(CtapError.ERR.UNAUTHORIZED_PERMISSION)) as request:
            with self.assertRaises(auth.AuthError) as caught:
                auth.unlock(self.key, self.ctap, use_uv=True, scope="settings")
        request.assert_called_once()
        self.assertEqual((caught.exception.code, caught.exception.extra["reason"]), ("unsupported", "uv_unlock"))
        self.assertTrue(auth.uv_limited(self.key, P.AUTHENTICATOR_CFG))
        self.assertFalse(auth.uv_limited(self.key, P.BIO_ENROLL))
        self.assertFalse(auth.uv_limited(self.key, P.CREDENTIAL_MGMT))
        auth.forget(self.key)
        self.assertTrue(auth.uv_limited(self.key, P.AUTHENTICATOR_CFG))
        with patch.object(ClientPin, "get_pin_token", return_value=b"synthetic-token"):
            auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope="settings")
        self.assertTrue(auth.is_unlocked(self.key, P.AUTHENTICATOR_CFG))
        auth.forget(self.key, disconnected=True)
        self.assertFalse(auth.uv_limited(self.key, P.AUTHENTICATOR_CFG))

    def test_legacy_fingerprint_limit_still_allows_passkeys(self):
        auth._uv_limited.add(self.key)
        self.assertFalse(auth.uv_limited(self.key, P.CREDENTIAL_MGMT))
        self.assertTrue(auth.uv_limited(self.key, P.BIO_ENROLL))

    def test_late_uv_refusal_after_disconnect_cannot_restore_capability_state(self):
        def refuse(*args, **kwargs):
            auth.forget(self.key, disconnected=True)
            raise CtapError(CtapError.ERR.UNAUTHORIZED_PERMISSION)
        with patch.object(ClientPin, "get_uv_token", side_effect=refuse) as request:
            with self.assertRaises(auth.AuthError) as caught:
                auth.unlock(self.key, self.ctap, use_uv=True, scope="settings")
        request.assert_called_once()
        self.assertEqual(caught.exception.code, "cancelled")
        self.assertFalse(auth.uv_limited(self.key, P.AUTHENTICATOR_CFG))
        self.assertNotIn(self.key, auth._pending)

    def test_late_scoped_unlock_after_cancel_lock_or_disconnect_is_discarded(self):
        for uv in (False, True):
            for action in ("cancel", "lock", "disconnect"):
                with self.subTest(uv=uv, action=action):
                    cancel = threading.Event()
                    def finish(*args, **kwargs):
                        if action == "cancel":
                            cancel.set()
                        else:
                            auth.forget(self.key, disconnected=action == "disconnect")
                        return b"synthetic-token"
                    with patch.object(ClientPin, "get_uv_token" if uv else "get_pin_token", side_effect=finish) as request:
                        with self.assertRaises(auth.AuthError) as caught:
                            auth.unlock(self.key, self.ctap, pin="synthetic-pin", use_uv=uv,
                                        scope="settings", cancel=cancel)
                    request.assert_called_once()
                    self.assertEqual(caught.exception.code, "cancelled")
                    self.assertFalse(auth.is_unlocked(self.key))
                    self.assertNotIn(self.key, auth._pending)

    def test_old_callers_keep_their_existing_permission_set(self):
        with patch.object(ClientPin, "get_pin_token", return_value=b"synthetic-token") as request:
            auth.unlock(self.key, self.ctap, pin="synthetic-pin")
        self.assertEqual(request.call_args.kwargs["permissions"], FULL)

    def test_bridge_forwards_scope_and_preserves_unscoped_call_contract(self):
        svc = object.__new__(service.KeyService)
        svc._scanner = SimpleNamespace(session=Mock(side_effect=lambda *a, **kw: nullcontext((None, self.ctap))))
        svc._unlock_waits = PendingOperations()
        for scope in (None, *SCOPES):
            args = {"token_id": self.key, "pin": "synthetic-pin"}
            if scope is not None:
                args["scope"] = scope
            with self.subTest(scope=scope), patch.object(auth, "unlock") as unlock:
                result = dispatch(svc, "unlock", args)
            self.assertTrue(result["ok"])
            self.assertTrue(result["data"]["unlocked"])
            self.assertEqual(unlock.call_args.kwargs.get("scope"), scope)
            self.assertFalse(unlock.call_args.kwargs["cancel"].is_set())

    def test_actual_client_pin_wire_path_preserves_legacy_device_support(self):
        shared = b"s" * 32
        protocol = PinProtocolV1()
        self.ctap.client_pin = Mock(return_value={ClientPin.RESULT.PIN_UV_TOKEN:
                                                protocol.encrypt(shared, b"t" * 32)})
        for supported, preview in ((False, False), (False, True), (True, False)):
            with self.subTest(permission_tokens=supported, preview=preview):
                self.ctap.info.options["pinUvAuthToken"] = supported
                self.ctap.info.options["credMgmt"] = not preview
                self.ctap.info.options["credentialMgmtPreview"] = preview
                self.ctap.info.versions = ["FIDO_2_1_PRE" if preview else "FIDO_2_1"]
                with patch.object(ClientPin, "_get_shared_secret", return_value=({}, shared)):
                    auth.unlock(self.key, self.ctap, pin="synthetic-pin", scope="passkeys")
                args, kwargs = self.ctap.client_pin.call_args
                self.assertEqual(args[1], ClientPin.CMD.GET_TOKEN_USING_PIN if supported
                                 else ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY)
                self.assertEqual(kwargs["permissions"], P.CREDENTIAL_MGMT if supported else None)
                self.assertIsNone(kwargs["permissions_rpid"])
                self.assertTrue(auth.is_unlocked(self.key, P.CREDENTIAL_MGMT))
                self.assertFalse(auth.is_unlocked(self.key, P.BIO_ENROLL))

    def test_other_scope_token_does_not_trigger_passkey_reads(self):
        auth._tokens[self.key] = auth.ManagementToken(1, b"synthetic-token", float("inf"), int(P.BIO_ENROLL))
        svc = object.__new__(service.KeyService)
        with patch.object(service.passkeys_mod, "list_passkeys") as read:
            result = svc._passkeys(self.key, self.ctap)
        self.assertFalse(result["unlocked"])
        read.assert_not_called()
