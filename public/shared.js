// Shared client helpers: escaping + party-feature UI (visual only — no audio anywhere)

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ─── Silent countdown ──────────────────────────────────────────────────────────

let countdownInterval = null;

function showCountdown(seconds) {
  const box = document.getElementById('countdown-box');
  if (!box) return;
  box.style.display = 'block';
  if (countdownInterval) clearInterval(countdownInterval);
  // Deadline is computed on THIS device's clock: server clock skew must not
  // shorten or kill the visible countdown. The server still owns the reveal.
  const endsAt = Date.now() + seconds * 1000;
  const tick = () => {
    const remain = Math.max(0, endsAt - Date.now());
    document.getElementById('countdown-num').textContent = Math.ceil(remain / 1000);
    document.getElementById('countdown-fill').style.width = (remain / (seconds * 1000) * 100) + '%';
    if (remain <= 0) { clearInterval(countdownInterval); countdownInterval = null; }
  };
  tick();
  countdownInterval = setInterval(tick, 250);
}

function hideCountdown() {
  if (countdownInterval) { clearInterval(countdownInterval); countdownInterval = null; }
  const box = document.getElementById('countdown-box');
  if (box) box.style.display = 'none';
}

// ─── Vote distribution chart ───────────────────────────────────────────────────

function renderVoteChart(distribution, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const entries = Object.entries(distribution || {});
  if (entries.length === 0) { container.innerHTML = ''; return; }
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  entries.sort((a, b) => b[1] - a[1]);
  container.innerHTML = entries.map(([name, count]) => {
    const pct = Math.round(count / total * 100);
    return `<div class="vote-chart-row">
      <span class="vote-chart-name">${escapeHtml(name)}</span>
      <div class="vote-chart-track"><div class="vote-chart-bar" style="width:${pct}%"></div></div>
      <span class="vote-chart-count">${count}</span>
    </div>`;
  }).join('');
}

// ─── Awards ────────────────────────────────────────────────────────────────────

function renderAwards(awards, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (!awards || awards.length === 0) { container.innerHTML = ''; return; }
  container.innerHTML = awards.map(a => `<div class="award-row">
    <span class="award-emoji">${escapeHtml(a.emoji)}</span>
    <span><span class="award-title">${escapeHtml(a.title)}</span>: ${escapeHtml(a.username)}
    <span class="award-detail">— ${escapeHtml(a.detail)}</span></span>
  </div>`).join('');
}

// ─── Confetti ──────────────────────────────────────────────────────────────────

function spawnConfetti() {
  const colors = ['#1ed760', '#ffd700', '#ff6b6b', '#4dabf7', '#f783ac', '#ffa94d'];
  for (let i = 0; i < 50; i++) {
    const el = document.createElement('div');
    el.className = 'confetti-piece';
    el.style.left = Math.random() * 100 + 'vw';
    el.style.background = colors[i % colors.length];
    el.style.animationDelay = (Math.random() * 0.5) + 's';
    el.style.animationDuration = (2 + Math.random() * 1.5) + 's';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4500);
  }
}

// ─── Spotify playlist export (shared by master + quizmaster) ────────────────
// getToken() -> Promise<string>. Throws Error('empty'|'scope'|'me'|'create'|'add').
async function spotifyExportPlaylist({ name, trackIds, getToken }) {
  const ids = [...new Set((trackIds || []).filter(t => /^[A-Za-z0-9]{22}$/.test(t || '')))];
  if (ids.length === 0) throw new Error('empty');

  const token = await getToken();
  const authJson = { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };

  const meRes = await fetch('https://api.spotify.com/v1/me', {
    headers: { 'Authorization': 'Bearer ' + token }
  });
  if (meRes.status === 403) throw new Error('scope');
  if (!meRes.ok) throw new Error('me');
  const me = await meRes.json();

  const plRes = await fetch('https://api.spotify.com/v1/users/' + encodeURIComponent(me.id) + '/playlists', {
    method: 'POST',
    headers: authJson,
    body: JSON.stringify({ name, description: 'Created with OnlyMIP MusicQuiz', public: false })
  });
  if (plRes.status === 403) throw new Error('scope');
  if (!plRes.ok) throw new Error('create');
  const pl = await plRes.json();

  for (let i = 0; i < ids.length; i += 100) {
    const uris = ids.slice(i, i + 100).map(id => 'spotify:track:' + id);
    const addRes = await fetch('https://api.spotify.com/v1/playlists/' + pl.id + '/tracks', {
      method: 'POST', headers: authJson, body: JSON.stringify({ uris })
    });
    if (!addRes.ok) throw new Error('add');
  }

  return {
    url: (pl.external_urls && pl.external_urls.spotify) || ('https://open.spotify.com/playlist/' + pl.id),
    count: ids.length
  };
}

// ─── Emoji reactions (float up the screen; used by phone + TV) ──────────────
const REACTION_EMOJIS = ['\u{1F525}', '\u{1F602}', '\u{1F631}', '\u{1F44F}', '❤️', '\u{1F389}'];

function spawnReaction(emoji) {
  const el = document.createElement('div');
  el.className = 'reaction-float';
  el.textContent = emoji;
  el.style.left = (8 + Math.random() * 84) + 'vw';
  el.style.fontSize = (1.8 + Math.random() * 1.4) + 'rem';
  el.style.setProperty('--drift', ((Math.random() * 60) - 30) + 'px');
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}
