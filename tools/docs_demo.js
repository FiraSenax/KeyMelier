// Demo bridge for documentation screenshots (tools/screenshots.py).
// Replaces the Python bridge with fictional data: no real keys, serials,
// accounts or history ever appear in the docs. English UI.
(function () {
  const now = Date.now();
  const iso = (msAgo) => new Date(now - msAgo).toISOString();
  const H = 3600e3, D = 24 * H;

  const verified = {
    ran: true, passed: true, status: 'VERIFIED', format: 'packed', aaguid_match: true,
    aaguid_from_auth_data: 'a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa', sig_valid: true, chain_valid: true,
    chain_depth: 1, subject_cn: 'Yubico U2F EE Serial 1234567890', error: null, inconclusive: null,
    checks: [
      { name: 'Format', passed: true, detail: 'packed' },
      { name: 'Request binding and user presence', passed: true, detail: 'RP ID hash and user-presence flag must match this test' },
      { name: 'AAGUID consistency', passed: true, detail: 'getInfo and authData agree' },
      { name: 'Signature', passed: true, detail: 'Packed signature and certificate profile verified' },
      { name: 'Cert chain', passed: true, detail: "Chain valid: leaf → root 'Yubico FIDO Root CA Serial 450203556'" },
      { name: 'Certificate matches model', passed: true, detail: 'Certificate AAGUID matches the device' },
    ],
  };

  const yk = {
    id: 'demo-yk5', path: 'demo-1', product_name: 'YubiKey OTP+FIDO+CCID', serial_number: '31415926',
    manufacturer: 'Yubico', aaguid: 'a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa',
    fido2_versions: ['U2F_V2', 'FIDO_2_0', 'FIDO_2_1'], extensions: ['credProtect', 'hmac-secret', 'largeBlobKey', 'credBlob', 'minPinLength'],
    options: { rk: true, up: true, plat: false, clientPin: true, credMgmt: true, authnrCfg: true, largeBlobs: true, pinUvAuthToken: true, setMinPINLength: true },
    pin_protocols: [2, 1], max_cred_count: 8, firmware_version_raw: 329474, firmware_version_str: '5.7.2',
    first_seen: iso(90 * D), vendor_id: 4176, product_id: 1031, form_factor: 'usb-a-keychain', fips: false, nfc: true,
    min_pin_length: 6, force_pin_change: false, remaining_disc_creds: 96, security_status: 'OK', cve_ids: [], advisories: [],
    mds_description: 'YubiKey 5 Series with NFC', mds_status: 'FIDO_CERTIFIED_L2', mds_authenticator_version: 329474,
    attestation: verified, algorithms: [-7, -8, -257], history_id: 'a1a1a1a1a1a1a1a1',
  };
  const t2 = {
    ...yk, id: 'demo-t2', path: 'demo-2', product_name: 'FIDO2 Security Key', serial_number: null, manufacturer: 'Token2',
    aaguid: 'ab32f0c6-2239-afbb-c470-d2ef4e254db7', firmware_version_str: '3.4', firmware_version_raw: null,
    form_factor: null, vendor_id: 13470, mds_description: 'TOKEN2 PIN+ Release3 FIDO2 Security Key',
    mds_status: 'FIDO_CERTIFIED_L1', algorithms: [-7, -8], history_id: 'b2b2b2b2b2b2b2b2',
    attestation: { ...verified, subject_cn: 'Token2 FIDO2 Attestation' },
  };
  const tokens = [yk, t2];

  const u = (...names) => names.map((name) => ({ name, display: '' }));
  const sites = [
    { rp_id: 'github.com', name: 'GitHub', count: 1, users: u('erika') },
    { rp_id: 'google.com', name: 'Google', count: 1, users: u('erika@example.com') },
    { rp_id: 'login.microsoft.com', name: 'Microsoft', count: 3, users: u('erika@contoso.com', 'admin.erika@contoso.com', 'erika@fabrikam.com') },
    { rp_id: 'bitwarden.com', name: 'Bitwarden', count: 1, users: u('erika@example.com') },
    { rp_id: 'proton.me', name: 'Proton', count: 1, users: u('erika@proton.me') },
  ];
  const oathAccounts = [
    { issuer: 'AWS', name: 'root@example.com' }, { issuer: 'GitHub', name: 'erika' },
    { issuer: 'Hetzner', name: 'erika@example.com' }, { issuer: 'Mastodon', name: '@erika@example.social' },
  ];
  const pgpKeys = [
    { slot: 'sig', algorithm: 'Ed25519', fingerprint: '8C3A 51F2 7D90 44E1 B6A2 0F5C 93D1 7E28 4B6F 0A19' },
    { slot: 'dec', algorithm: 'Curve25519', fingerprint: '2F71 C0A9 55E3 9B18 D46C 7A02 E1F8 36B4 90CD 5E73' },
    { slot: 'aut', algorithm: 'Ed25519', fingerprint: 'A907 3D5E C1B8 62F4 0E9A 7C31 58D2 B6E0 4F19 83AC' },
  ];

  const history = {
    a1a1a1a1a1a1a1a1: {
      key_id: 'a1a1a1a1a1a1a1a1', first_seen: iso(90 * D), last_seen: iso(1 * H), connect_count: 142, label: 'Everyday key',
      snapshot: { ...yk }, sites, sites_updated: iso(2 * D),
      inventory: {
        oath: { items: oathAccounts, updated: iso(1 * D) },
        openpgp: { items: pgpKeys, updated: iso(3 * D) },
        piv: { items: [{ slot: '9a', label: '9A: CN=Erika Mustermann' }], updated: iso(3 * D) },
        otp: { items: [{ otp_slot: 1 }], updated: iso(3 * D) },
      },
      events: [
        { ts: iso(30 * D), type: 'pin_changed' },
        { ts: iso(20 * D), type: 'oath_added', site: 'Hetzner', user: 'erika@example.com' },
        { ts: iso(5 * D), type: 'pgp_generated', site: 'Erika Mustermann <erika@example.com>' },
        { ts: iso(2 * D), type: 'function_test', passed: true },
        { ts: iso(1 * H + 60e3), type: 'connected' },
        { ts: iso(1 * H), type: 'attestation', passed: true, status: 'VERIFIED' },
      ],
    },
    b2b2b2b2b2b2b2b2: {
      key_id: 'b2b2b2b2b2b2b2b2', first_seen: iso(60 * D), last_seen: iso(2 * H), connect_count: 18, label: 'Backup key',
      snapshot: { ...t2 }, sites: [sites[0], sites[1], { ...sites[2], count: 2, users: u('erika@contoso.com', 'erika@fabrikam.com') }],
      sites_updated: iso(10 * D),
      inventory: { oath: { items: oathAccounts.slice(1, 3), updated: iso(10 * D) } },
      events: [{ ts: iso(2 * H), type: 'connected' }],
    },
    c3c3c3c3c3c3c3c3: {
      key_id: 'c3c3c3c3c3c3c3c3', first_seen: iso(400 * D), last_seen: iso(45 * D), connect_count: 63, label: 'Old office key',
      snapshot: { ...yk, serial_number: '27182818', firmware_version_str: '5.2.7', mds_description: 'YubiKey 5C Nano',
                  form_factor: 'usb-c-nano', security_status: 'UNKNOWN', attestation: null },
      sites: [{ rp_id: 'github.com', name: 'GitHub', count: 1 }, { rp_id: 'aws.amazon.com', name: 'AWS', count: 1 }],
      sites_updated: iso(50 * D), lost_since: iso(3 * D), events: [{ ts: iso(3 * D), type: 'marked_lost' }],
    },
  };
  const summary = (e) => { const { events, ...rest } = e; return rest; };

  const piv = {
    version: '5.7.2', pin: { attempts: 3, default: false, puk_attempts: 3, puk_default: false },
    management_key: { protected: true, type: 'AES192', default: false, touch: false },
    slots: [
      { slot: '9a', cert: { subject: 'CN=Erika Mustermann,O=Example GmbH', issuer: 'CN=Example Issuing CA', self_signed: false,
          not_before: iso(200 * D), not_after: new Date(now + 530 * D).toISOString(), expired: false, expires_soon: false,
          algorithm: 'ECC P-256', sha256: '5E0C…' },
        key: { type: 'ECCP256', generated: true, pin_policy: 'once', touch_policy: 'cached' } },
      { slot: '9c', cert: null, key: null }, { slot: '9d', cert: null, key: null }, { slot: '9e', cert: null, key: null },
    ],
    can_delete_key: true, key_types: ['ECCP256', 'ECCP384', 'RSA2048', 'RSA3072', 'RSA4096', 'ED25519'], metadata: true,
  };

  const oathState = () => {
    const period = 30;
    const validTo = Math.ceil(now / 1000 / period) * period;
    const codes = ['482 913', '077 164', '903 552', '615 208'];
    return {
      password: true, unlocked: true, version: '5.7.2', can_rename: true,
      accounts: oathAccounts.map((a, i) => ({ id: `acc${i}`, issuer: a.issuer, name: a.name, type: 'TOTP', period,
        touch: i === 0, code: i === 0 ? null : codes[i].replace(' ', ''), valid_to: i === 0 ? null : validTo })),
    };
  };

  const settings = { history_enabled: true, remember_sites: true, lang: 'en', stateless: false, system_languages: ['en-US'],
    onboarding_done: true, platform: 'darwin', build: { signed: false, notarized: false } };
  const api = {
    get_settings: () => ({ ...settings }),
    set_settings: ({ values }) => Object.assign(settings, values) && { ...settings },
    data_status: () => ({ advisories: { source: 'downloaded', updated: iso(4 * D), count: 14 },
      mds: { cached: true, fetched_at: iso(6 * H), entry_count: 531, serial: 291, current: true, next_update: new Date(now + 20 * D).toISOString().slice(0, 10), revocation_checked: true, verified: true },
      last_check: iso(6 * H), app: { current: '1.7.0', latest: '1.7.0', newer: false } }),
    mds_status: () => api.data_status().mds,
    tokens: () => ({ tokens }),
    history_list: () => ({ keys: Object.values(history).map(summary) }),
    history_get: ({ kid }) => history[kid],
    sync_status: () => ({ available: true, active: true, configured: true, folder: '/Users/erika/Library/Mobile Documents/com~apple~CloudDocs/KeyMelier',
      device: '3f9a1c07b2d84e65', device_name: 'Erikas MacBook Pro', last_sync: iso(2 * 60e3), min_passphrase: 10, problem: null,
      devices: [{ device: 'a', name: 'Office PC', written: iso(20 * 60e3) }, { device: 'b', name: 'Gaming PC', written: iso(3 * H) },
                { device: 'c', name: 'Mac mini', written: iso(1 * D) }], errors: [] }),
    history_replace: ({ kid, new_kid }) => {
      if (!new_kid) delete history[kid].replace;
      else if (history[kid].replace?.new !== new_kid) history[kid].replace = { new: new_kid, since: iso(0), done: [] };
      return summary(history[kid]);
    },
    history_replace_done: ({ kid, item, done }) => {
      if (!history[kid]?.replace) return summary(history[kid]);   // like the backend: nothing to tick
      const list = new Set(history[kid].replace.done);
      if (done) list.add(item); else list.delete(item);
      history[kid].replace.done = [...list];
      return summary(history[kid]);
    },
    pin_status: () => ({ supported: true, is_set: true, retries: 8, power_cycle_required: false, min_length: 6, max_bytes: 63, force_change: false, uv: null, uv_retries: null }),
    config: () => ({ supported: true, pin_set: true, uv_unlock: false, min_pin_length: 6, can_set_min_pin: true, force_pin_change: false, always_uv: false, unlocked: true }),
    passkeys: () => ({ supported: true, pin_set: true, uv_unlock: false, rename: true, unlocked: true, existing: 5, remaining: 95,
      rps: sites.map((s, i) => ({ rp_id: s.rp_id, rp_name: s.name, rp_id_hash: String(i).repeat(64).slice(0, 64),
        credentials: [{ credential_id: `c${i}`, user_id: `u${i}`, user_name: i === 2 ? 'erika@example.com' : 'erika',
          display_name: 'Erika Mustermann', cred_protect: 2, large_blob: false }] })) }),
    fingerprints: () => ({ supported: false }),
    function_test_info: () => ({ needs_pin: false }),
    card_apps: ({ token_id }) => ({ reader: true, apps: token_id === 'demo-t2'
      ? { oath: false, piv: false, openpgp: true, otp: false }
      : { oath: true, piv: true, openpgp: true, otp: true, interfaces: true } }),
    oath: oathState,
    openpgp: () => ({ spec: '3.4', serial: '31415926', yubikey: true,
      keys: pgpKeys.map((k) => ({ ...k, present: true, created: iso(5 * D), origin: 'generated', touch: k.slot === 'dec' ? 'off' : 'cached' })),
      signature_counter: 37, pin: { user: 3, admin: 3, reset: 0, sign_every_time: false },
      name: 'Erika Mustermann', url: 'https://example.com/erika.asc', can_touch: true, algorithms: ['ed25519', 'p256', 'rsa2048', 'rsa4096'] }),
    piv: () => piv,
    otp: () => ({ slots: [{ slot: 1, configured: true, touch: true }, { slot: 2, configured: true, touch: false }], led_inverted: false, input_monitoring: true }),
    unlock: () => ({ unlocked: true, ttl: 300 }),
    read_contents: () => ({ sites: 5, oath: 4, openpgp: 3, piv: 1 }),
    lock: () => ({ unlocked: false }),
    interfaces: () => ({ locked: false, transports: {
      usb: { OTP: true, U2F: true, FIDO2: true, OATH: true, PIV: true, OPENPGP: true, HSMAUTH: false },
      nfc: { OTP: false, U2F: true, FIDO2: true, OATH: true, PIV: false, OPENPGP: false, HSMAUTH: false } } }),
  };

  window.__demoCalls = [];
  window.pywebview = {
    api: {
      call: async (method, args) => {
        window.__demoCalls.push(method);   // observed by tests/ui (e.g. no unlock after a cancel)
        const fn = api[method];
        if (!fn) return { ok: false, error: 'Not available in the demo', code: 'demo' };
        return { ok: true, data: JSON.parse(JSON.stringify(fn(args || {}))) };
      },
      client_log: async () => true, client_error: async () => true, set_ui_language: async () => true,
      copy_text: async () => true, open_url: async () => true, gpg_available: async () => false,
      open_licenses: async () => true, choose_folder: async () => null,
      save_text: async (name, text, priv) => { window.__lastSave = { name, text, priv }; return `/tmp/${name}`; },
    },
  };

  // Scene from the URL hash, run once the UI has loaded its data
  window.__demoScene = decodeURIComponent((location.hash || '#overview').slice(1));
})();
