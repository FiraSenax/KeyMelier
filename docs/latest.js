// Fills in the latest release (version, date, direct downloads) from GitHub.
// Without JavaScript or network the static links to /releases/latest remain.
(function () {
  const repo = 'FiraSenax/KeyMelier';
  fetch(`https://api.github.com/repos/${repo}/releases/latest`, { headers: { Accept: 'application/vnd.github+json' } })
    .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
    .then((rel) => {
      if (rel.draft || rel.prerelease || !/^v\d+\.\d+\.\d+$/.test(rel.tag_name || '')) return;
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
      // Only a verified release workflow writes this marker. Older releases,
      // failed requests and malformed metadata keep the neutral fallback.
      const markers = [...String(rel.body || '').matchAll(/<!-- keymelier-signing: (\{[^\r\n]*\}) -->/g)];
      if (markers.length !== 1) return;
      let status;
      try { status = JSON.parse(markers[0][1]); } catch { return; }
      if (status.schema !== 1 || typeof status.windows !== 'boolean' || typeof status.macos !== 'boolean') return;
      if (asset('KeyMelier-Windows-Setup.exe')) {
        document.querySelectorAll('[data-windows-signing]').forEach((el) => {
          el.textContent = status.windows
            ? `Windows ${rel.tag_name} is Authenticode signed with a Certum certificate and a trusted timestamp. SmartScreen may still show a reputation warning.`
            : `Windows ${rel.tag_name} is not code-signed. Check its release notes and SHA-256 checksums before installing.`;
        });
      }
    })
    .catch(() => { /* keep the static fallback links */ });
})();
