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
    otp: () => switchTab('otp'),
    settings: () => switchTab('settings'),
    history: () => switchTab('history'),
    details: () => switchTab('details'),
    accounts: () => showAccountsView(),
    shared: () => { appSettings.personal_mode = false; lostKid = 'c3c3c3c3c3c3c3c3'; showBackupView(); },
    backup: () => showBackupView(),
    lost: () => { showBackupView(); lostKid = 'c3c3c3c3c3c3c3c3'; renderBackupView(); document.querySelector('#bk-lost-select')?.scrollIntoView(); },
  };
  const run = () => {
    if (!tokens.size) return setTimeout(run, 50);
    selectToken('demo-yk5');
    setTimeout(() => (scenes[window.__demoScene] || scenes.overview)(), 200);
  };
  setTimeout(run, 100);
})();
