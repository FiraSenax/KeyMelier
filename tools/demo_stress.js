// Large, deterministic demo data for UI load tests (tests/ui/ui_stress.cjs):
// the demo page with #stress replaces its history with 12 keys and a few
// hundred accounts – plugged in, offline, lost, partly searched, never read,
// stale – with very long, German and Japanese names. Fictional data only;
// the same seed always gives the same data.
window.__demoStress = function (history, base, now) {
  let seed = 20260927;   // mulberry32
  const rnd = () => {
    seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = list => list[Math.floor(rnd() * list.length)];
  const D = 86400e3;
  const iso = msAgo => new Date(now - msAgo).toISOString();

  const services = [
    ['GitHub', 'github.com'], ['Google', 'google.com'], ['Microsoft', 'login.microsoft.com'], ['Bitwarden', 'bitwarden.com'],
    ['Proton', 'proton.me'], ['Amazon Web Services', 'aws.amazon.com'], ['Cloudflare', 'cloudflare.com'], ['GitLab', 'gitlab.com'],
    ['Dropbox', 'dropbox.com'], ['1Password', '1password.com'], ['Nextcloud (Verein)', 'cloud.verein.example.org'],
    ['Bundesagentur für Arbeitsvermittlung und Weiterbildungsförderung – Testportal für Arbeitgeberinnen und Arbeitgeber',
      'arbeitsvermittlung-und-weiterbildungsfoerderung.example.de'],
    ['楽天市場テストアカウント', 'rakuten-test.example.jp'], ['みずほ銀行（テスト用ログイン）', 'mizuho-test.example.co.jp'],
    ['Stadtwerke Musterstadt Kundenportal', 'kundenportal.stadtwerke-musterstadt.example.de'],
    ['Krankenversicherung Beispiel', 'meine.kv-beispiel.example.de'], ['Hetzner', 'accounts.hetzner.com'],
    ['Mastodon', 'example.social'], ['Discord', 'discord.com'], ['PayPal', 'paypal.com'], ['Shopify', 'accounts.shopify.com'],
    ['Okta (Contoso)', 'contoso.okta.com'], ['Vercel', 'vercel.com'], ['npm', 'npmjs.com'], ['PyPI', 'pypi.org'],
    ['Twitch', 'twitch.tv'], ['LinkedIn', 'linkedin.com'], ['Namecheap', 'namecheap.com'], ['Tailscale', 'login.tailscale.com'],
    ['Sparkasse Beispielstadt', 'banking.sparkasse-beispiel.example.de'], ['Finanzamt ELSTER (Test)', 'elster.example.de'],
    ['Universität Beispielhausen – Hochschulrechenzentrum Single Sign-on', 'sso.uni-beispielhausen.example.de'],
    ['日本郵便テスト', 'post-test.example.jp'], ['Atlassian', 'id.atlassian.com'], ['Slack', 'slack.com'],
    ['Zoom', 'zoom.us'], ['Apple', 'appleid.apple.com'], ['Adobe', 'adobe.com'], ['Figma', 'figma.com'], ['Notion', 'notion.so'],
  ];
  const people = ['erika', 'max', 'admin', 'test', 'erika.mustermann', 'buchhaltung', 'ops', 'dev', 'familie',
    'max.mustermann.sehr.langer.kontoname.fuer.lasttests.1234567890', 'やまだ・たろう', 'シュトレステスト'];
  const account = svc => {
    const who = pick(people);
    const host = svc[1].split('.').slice(-2).join('.');
    return rnd() < 0.7 ? `${who}@${host}` : `${who}${Math.floor(rnd() * 90) + 10}`;
  };

  // 12 keys: 2 plugged in (the demo tokens), the rest offline in different states
  const ids = ['a1a1a1a1a1a1a1a1', 'b2b2b2b2b2b2b2b2',
    ...Array.from({ length: 10 }, (_, i) => (0xd0 + i).toString(16).repeat(8))];
  const labels = ['Everyday key', 'Backup key', 'Schlüssel im Tresor des Bürogebäudes Nord (Ersatz für den verlorenen Arbeitsschlüssel)',
    'バックアップ用セキュリティキー（金庫）', 'Old office key', 'Travel key', 'Family key', 'Server room key',
    'Ungeprüfter Schlüssel aus der Schublade', 'Lab key', 'Admin key', 'Spare key'];
  const state = ['plugged', 'plugged', 'offline', 'offline', 'lost', 'stale', 'offline', 'partial', 'never', 'offline', 'lost', 'offline'];

  // ~300 distinct accounts, each on 1–3 keys (not on never-read keys)
  const readable = ids.filter((_, i) => state[i] !== 'never');
  const holders = new Map(ids.map(id => [id, new Map()]));
  const seen = new Set();
  for (let n = 0; n < 300; n++) {
    const svc = pick(services);
    const name = account(svc);
    if (seen.has(`${svc[1]}|${name}`)) continue;
    seen.add(`${svc[1]}|${name}`);
    const copies = 1 + Math.floor(rnd() * 3);
    for (let c = 0; c < copies; c++) {
      const kid = pick(readable);
      const sites = holders.get(kid);
      if (!sites.has(svc[1])) sites.set(svc[1], { rp_id: svc[1], name: svc[0], users: [] });
      const s = sites.get(svc[1]);
      if (!s.users.some(u => u.name === name)) s.users.push({ name, display: rnd() < 0.3 ? 'Erika Mustermann' : '' });
    }
  }
  // Passkeys without a known account name (older keys) on a few sites
  holders.get(ids[4]).set('discord.com', { rp_id: 'discord.com', name: 'Discord', count: 2, users: [] });
  holders.get(ids[6]).set('twitch.tv', { rp_id: 'twitch.tv', name: 'Twitch', count: 3, users: [{ name: '', display: 'Administrator' }] });

  const oath = (count) => Array.from({ length: count }, () => { const svc = pick(services); return { issuer: svc[0], name: account(svc) }; });

  for (const k of Object.keys(history)) delete history[k];
  ids.forEach((id, i) => {
    const st = state[i];
    const sites = [...holders.get(id).values()].map(s => ({ ...s, count: s.count || s.users.length }));
    const snapshot = { ...base, id: `hist-${id}`, history_id: id, serial_number: String(10000000 + i * 7919),
      product_name: i % 2 ? 'FIDO2 Security Key' : 'YubiKey OTP+FIDO+CCID', security_status: st === 'never' ? 'UNKNOWN' : 'OK',
      remaining_disc_creds: Math.max(0, 100 - sites.length) };
    const entry = { key_id: id, first_seen: iso((400 - i * 20) * D), last_seen: iso((st === 'plugged' ? 0.01 : 3 + i * 4) * D),
      connect_count: 5 + i * 11, label: labels[i], snapshot, events: [{ ts: iso(1 * D), type: 'connected' }] };
    if (st !== 'never') {
      entry.sites = sites;
      entry.sites_updated = iso((st === 'stale' ? 200 : 2 + i) * D);
      entry.inventory = { oath: { items: oath(4 + (i % 5)), updated: entry.sites_updated } };
    }
    if (st === 'partial') {
      const asked = sites.slice(0, 6).map(s => s.rp_id);
      entry.probe = { complete: false };
      entry.sites_probed = asked.length + 12;
      entry.probe_rp = Object.fromEntries([...asked, 'twitch.tv', 'zoom.us'].map(rp => [rp, asked.includes(rp)]));
    }
    if (st === 'lost') { entry.lost_since = iso((5 + i) * D); entry.events.push({ ts: entry.lost_since, type: 'marked_lost' }); }
    history[id] = entry;
  });
  return { keys: ids.length, states: state };
};
