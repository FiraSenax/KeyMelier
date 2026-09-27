"""Find passkeys on keys that cannot list them (FIDO 2.0, e.g. YubiKey 5.1).

Such keys have no credential management, but they answer a sign-in request
for a given website. KeyMelier asks site by site – silently (up=false, no
touch) – whether a discoverable credential exists, and walks all accounts of
that site with getNextAssertion. With the PIN (user verification) the key
also returns the account names (UPNs); without it only opaque user IDs.

A hit only shows that the key holds a credential for that rpId – it is not
a sign-in at the real service. Only sites on the candidate list are checked,
and every hit increments that credential's signature counter (harmless).

Result per site: found | none (the key said "no credentials" – the only
negative proof) | unsupported | uv_required | error (nothing is known).
"""

import hashlib
import logging
import os

from fido2tool_core.auth import AuthError

logger = logging.getLogger(__name__)

# rpIds of common services that offer passkeys (the exact rpId matters)
COMMON_RP_IDS = [
    "google.com", "login.microsoft.com", "login.live.com", "microsoft.com", "github.com", "gitlab.com",
    "amazon.com", "aws.amazon.com", "signin.aws.amazon.com", "apple.com", "paypal.com", "ebay.com",
    "facebook.com", "x.com", "twitter.com", "linkedin.com", "dropbox.com", "bitwarden.com",
    "vault.bitwarden.com", "1password.com", "proton.me", "account.proton.me", "cloudflare.com",
    "dash.cloudflare.com", "adobe.com", "shopify.com", "atlassian.com", "id.atlassian.com",
    "npmjs.com", "pypi.org", "docker.com", "hetzner.com", "accounts.hetzner.com", "discord.com",
    "tiktok.com", "nintendo.com", "okta.com", "yubico.com", "webauthn.io", "passkeys.io",
    "binance.com", "coinbase.com", "kraken.com", "stripe.com", "salesforce.com", "zoho.com",
    "tailscale.com", "login.tailscale.com", "hubspot.com", "mailchimp.com", "vercel.com",
    "netlify.com", "digitalocean.com", "cloud.digitalocean.com", "ionos.de", "web.de", "gmx.net",
    "mail.de", "posteo.de", "t-online.de", "sparkasse.de", "dkb.de", "n26.com", "ing.de",
    "comdirect.de", "check24.de", "otto.de", "zalando.de", "idealo.de",
]

MAX_ACCOUNTS_PER_SITE = 50


def candidates(known: list[str], extra: list[str]) -> list[str]:
    seen, out = set(), []
    for rp in [*known, *extra, *COMMON_RP_IDS]:
        rp = (rp or "").strip().lower().removeprefix("https://").split("/")[0]
        if rp and "." in rp and len(rp) <= 253 and rp not in seen:
            seen.add(rp)
            out.append(rp)
    return out[:400]


def _user(entity) -> dict:
    entity = entity or {}
    return {"name": str(entity.get("name") or "")[:200], "display": str(entity.get("displayName") or "")[:200]}


class Cancelled(Exception):
    pass


def _classify(err) -> str:
    """Map a CTAP error of the silent query to a result status."""
    from fido2.ctap import CtapError
    code = getattr(err, "code", None)
    ERR = CtapError.ERR
    if code == ERR.NO_CREDENTIALS:
        return "none"
    if code in (ERR.UNSUPPORTED_OPTION, ERR.INVALID_OPTION, ERR.UNSUPPORTED_ALGORITHM, ERR.INVALID_COMMAND):
        return "unsupported"
    if code in (ERR.PUAT_REQUIRED, ERR.OPERATION_DENIED, ERR.UV_INVALID):
        return "uv_required"
    return "error"


def probe(ctap2, rp_ids: list[str], pin: str | None = None, progress=None, cancelled=None) -> dict:
    """Ask the key about every rpId. Returns
    {"complete": bool, "results": [{rp_id, status, count?, users?, partial?}]}.

    PIN problems abort the whole scan (AuthError) – the PIN is sent once and
    never retried. A cancel or an unexpected transport failure ends the scan
    early with complete=False; the results so far are kept.
    """
    from fido2.ctap import CtapError
    from fido2.ctap2.pin import ClientPin

    token = protocol = None
    if pin:
        client_pin = ClientPin(ctap2)
        try:
            token = client_pin.get_pin_token(pin)   # one attempt; errors abort the scan
            protocol = client_pin.protocol
        except CtapError as e:
            from fido2tool_core.auth import map_ctap_error
            raise map_ctap_error(e, client_pin) from None

    def ask(rp_id) -> dict:
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        kwargs = {"options": {"up": False}}
        if token is not None:
            kwargs.update(pin_uv_param=protocol.authenticate(token, client_data_hash),
                          pin_uv_protocol=protocol.VERSION)
        try:
            first = ctap2.get_assertion(rp_id, client_data_hash, **kwargs)
        except CtapError as e:
            if e.code in (CtapError.ERR.PIN_AUTH_INVALID, CtapError.ERR.PIN_INVALID,
                          CtapError.ERR.PIN_BLOCKED, CtapError.ERR.PIN_AUTH_BLOCKED):
                raise AuthError("The PIN is no longer accepted – the search was stopped.", "pin_invalid") from None
            return {"rp_id": rp_id, "status": _classify(e)}
        total = first.number_of_credentials or 1
        users = [_user(first.user)]
        partial = False
        for _ in range(min(total, MAX_ACCOUNTS_PER_SITE) - 1):
            try:
                users.append(_user(ctap2.get_next_assertion().user))
            except Exception as e:  # the count is known even if walking the accounts fails
                logger.debug("getNextAssertion %s: %s", rp_id, e)
                partial = True
                break
        result = {"rp_id": rp_id, "status": "found", "count": total, "users": users}
        if partial or total > MAX_ACCOUNTS_PER_SITE:
            result["partial"] = True
        return result

    results, complete = [], True
    for i, rp_id in enumerate(rp_ids):
        if cancelled and cancelled():
            complete = False
            break
        if progress:
            progress(i, len(rp_ids))
        try:
            results.append(ask(rp_id))
        except AuthError:
            raise
        except Exception as e:  # transport failure (key removed, another program, timeout)
            logger.debug("probe %s: %s", rp_id, e)
            try:  # one retry of the query – never involves the PIN again
                results.append(ask(rp_id))
            except AuthError:
                raise
            except Exception as e2:
                logger.info("Passkey search stopped at %s: %s", rp_id, e2)
                results.append({"rp_id": rp_id, "status": "error"})
                complete = False
                break
    if progress:
        progress(len(results), len(rp_ids))
    return {"complete": complete, "results": results}
