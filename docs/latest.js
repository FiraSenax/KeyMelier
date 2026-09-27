// Fills in the latest release (version, date, direct downloads) from GitHub.
// Without JavaScript or network the static links to /releases/latest remain.
(function () {
  const repo = 'FiraSenax/KeyMelier';
  fetch(`https://api.github.com/repos/${repo}/releases/latest`, { headers: { Accept: 'application/vnd.github+json' } })
    .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
    .then((rel) => {
      const asset = (name) => (rel.assets || []).find((a) => a.name === name);
      const date = new Date(rel.published_at).toLocaleDateString('en', { year: 'numeric', month: 'long', day: 'numeric' });
      document.querySelectorAll('[data-latest-version]').forEach((el) => { el.textContent = `${rel.tag_name} · ${date}`; });
      // Installer first (disk image / setup); the ZIP only for releases without one
      const links = [[['KeyMelier-macOS.dmg', 'KeyMelier-macOS.zip'], 'macOS'],
        [['KeyMelier-Windows-Setup.exe', 'KeyMelier-Windows.zip'], 'Windows'],
        [['KeyMelier-Linux-x86_64.AppImage'], 'Linux'],
        [['KeyMelier-Linux-aarch64.AppImage'], 'Linux ARM64']];
      document.querySelectorAll('[data-latest-downloads]').forEach((el) => {
        el.textContent = '';
        for (const [names, label] of links) {
          const a = names.map(asset).find(Boolean);
          if (!a) continue;
          const link = document.createElement('a');
          link.className = 'btn primary';
          link.href = a.browser_download_url;
          link.textContent = `Download for ${label}`;
          el.appendChild(link);
        }
        const notes = document.createElement('a');
        notes.className = 'btn ghost';
        notes.href = rel.html_url;
        notes.textContent = 'Release notes & checksums';
        el.appendChild(notes);
      });
    })
    .catch(() => { /* keep the static fallback links */ });
})();
