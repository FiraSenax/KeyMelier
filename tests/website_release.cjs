// Exercise the real website script with GitHub responses, without a network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(require('node:path').join(__dirname, '../docs/latest.js'), 'utf8');
const marker = (windows) => `<!-- keymelier-signing: ${JSON.stringify({schema: 1, macos: true, windows})} -->`;
const stable = {tag_name: 'v1.8.6', published_at: '2026-10-26T12:00:00Z', draft: false, prerelease: false,
  assets: [{name: 'KeyMelier-Windows-Setup.exe'}], body: marker(true)};
async function render(release, fail = false) {
  const el = {textContent: 'fallback'};
  vm.runInNewContext(script, {
    fetch: async () => { if (fail) throw new Error('offline'); return {ok: true, json: async () => release}; },
    document: {querySelectorAll: (selector) => selector === '[data-windows-signing]' ? [el] : []},
  });
  await new Promise((resolve) => setImmediate(resolve));
  return el.textContent;
}
(async () => {
  assert.match(await render(stable), /v1\.8\.6 is Authenticode signed with a Certum certificate/);
  assert.match(await render({...stable, body: marker(false)}), /not code-signed/);
  for (const variant of [
    {...stable, body: ''}, {...stable, body: marker('true')}, {...stable, body: '{broken'},
    {...stable, body: marker(true) + marker(false)}, {...stable, assets: []},
    {...stable, tag_name: 'v1.8.6-rc.2'}, {...stable, prerelease: true}, {...stable, draft: true},
  ]) assert.equal(await render(variant), 'fallback');
  assert.equal(await render(stable, true), 'fallback');
  console.log('Website release status: signed, unsigned, absent/malformed metadata, RC, draft and offline cases passed.');
})().catch((error) => { console.error(error); process.exitCode = 1; });
