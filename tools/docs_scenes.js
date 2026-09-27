// Scene selection for documentation screenshots (after app.js has loaded).
(function () {
  const scenes = {
    overview: () => {},
    pin: () => switchTab('pin'),
    passkeys: () => switchTab('passkeys'),
    security: () => switchTab('security'),
    oath: () => switchTab('oath'),
    openpgp: () => switchTab('openpgp'),
    'openpgp-generate': () => { switchTab('openpgp'); setTimeout(() => { pgpForm = 'generate'; renderPgp(); }, 400); },
    piv: () => switchTab('piv'),
    advanced: () => { switchTab('piv'); setTimeout(() => setTabMenu(true), 300); },
    'advanced-de': () => { changeLang('de', false); switchTab('piv'); setTimeout(() => setTabMenu(true), 300); },
    otp: () => switchTab('otp'),
    settings: () => switchTab('settings'),
    history: () => switchTab('history'),
    details: () => switchTab('details'),
    accounts: () => showAccountsView(),
    unlock: () => { quickLockToggle('demo-yk5'); },
    'unlock-done': () => { quickLockToggle('demo-yk5'); setTimeout(() => { document.querySelector('.ql-pin').value = '123456'; quickUnlockSubmit(); }, 300); },
    shared: () => { appSettings.personal_mode = false; lostKid = 'c3c3c3c3c3c3c3c3'; showBackupView(); },
    backup: () => showBackupView(),
    sync: () => { showBackupView(); setTimeout(() => document.getElementById('sync-card')?.scrollIntoView(), 400); },
    replace: () => {
      const old = historyKeys.get('a1a1a1a1a1a1a1a1');
      old.replace = { new: 'b2b2b2b2b2b2b2b2', since: new Date().toISOString(), done: ['pk:github.com|erika', 'oath:hetzner|erika@example.com'] };
      replaceOld = old.key_id;
      showBackupView();
      document.getElementById('rp-card')?.scrollIntoView();
    },
    lost: () => { showBackupView(); lostKid = 'c3c3c3c3c3c3c3c3'; renderBackupView(); document.querySelector('#bk-lost-select')?.scrollIntoView(); },
  };
  const run = () => {
    if (!tokens.size) return setTimeout(run, 50);
    selectToken('demo-yk5');
    setTimeout(() => (scenes[window.__demoScene] || scenes.overview)(), 200);
  };
  setTimeout(run, 100);
})();
