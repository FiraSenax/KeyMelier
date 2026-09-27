"""Find passkeys on keys that cannot list them (FIDO 2.0, e.g. YubiKey 5.1).

Such keys have no credential management, but they answer a sign-in request
for a given website. KeyMelier asks site by site – silently (up=false, no
touch) – whether a discoverable credential exists, and walks all accounts of
that site with getNextAssertion. With the PIN (user verification) the key
also returns the account names (UPNs); without it only opaque user IDs.

Limits: only sites on the candidate list can be found, and every hit
increments that credential's signature counter (harmless for websites).
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


def probe(ctap2, rp_ids: list[str], pin: str | None = None, progress=None) -> list[dict]:
    """Return [{rp_id, count, users:[{name, display}]}] for the sites found."""
    from fido2.ctap import CtapError
    from fido2.ctap2.pin import ClientPin

    token = protocol = None
    if pin:
        try:
            client_pin = ClientPin(ctap2)
            token = client_pin.get_pin_token(pin)
            protocol = client_pin.protocol
        except CtapError as e:
            from fido2tool_core.auth import map_ctap_error
            raise map_ctap_error(e, client_pin) from None

    def ask(rp_id):
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        kwargs = {"options": {"up": False}}
        if token is not None:
            kwargs.update(pin_uv_param=protocol.authenticate(token, client_data_hash),
                          pin_uv_protocol=protocol.VERSION)
        try:
            first = ctap2.get_assertion(rp_id, client_data_hash, **kwargs)
        except CtapError as e:
            if e.code == CtapError.ERR.NO_CREDENTIALS:
                return None
            if e.code in (CtapError.ERR.PIN_AUTH_INVALID, CtapError.ERR.PIN_INVALID):
                raise AuthError("The PIN is no longer accepted – try again.", "pin_invalid") from None
            logger.debug("probe %s: %s", rp_id, e)
            return None
        total = first.number_of_credentials or 1
        users = [_user(first.user)]
        for _ in range(min(total, MAX_ACCOUNTS_PER_SITE) - 1):
            users.append(_user(ctap2.get_next_assertion().user))
        return {"rp_id": rp_id, "count": total, "users": users}

    found = []
    for i, rp_id in enumerate(rp_ids):
        if progress:
            progress(i, len(rp_ids))
        for attempt in (1, 2):
            try:
                hit = ask(rp_id)
                break
            except AuthError:
                raise
            except Exception as e:  # e.g. another program talked to the key in between
                logger.debug("probe %s attempt %d: %s", rp_id, attempt, e)
                hit = None
        if hit:
            found.append(hit)
    if progress:
        progress(len(rp_ids), len(rp_ids))
    return found
