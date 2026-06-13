const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);

// ─── Security Headers ──────────────────────────────────────────────────────────
// NOTE: Spotify Web Playback SDK uses EME/Widevine which is sensitive to
// Cross-Origin-Resource-Policy and Origin-Agent-Cluster headers. Disable those.
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  crossOriginResourcePolicy: false,
  crossOriginEmbedderPolicy: false,
  originAgentCluster: false
}));

// ─── Rate Limiting ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, try again later' }
});
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;
const MASTER_PASSWORD = process.env.MASTER_PASSWORD;
if (!MASTER_PASSWORD) {
  console.error('FATAL: MASTER_PASSWORD environment variable is not set. Refusing to start.');
  process.exit(1);
}

// Constant-time password compare to prevent timing-based brute force
const MASTER_PASSWORD_BUF = Buffer.from(MASTER_PASSWORD, 'utf8');
function checkPassword(supplied) {
  if (typeof supplied !== 'string') return false;
  const buf = Buffer.from(supplied, 'utf8');
  if (buf.length !== MASTER_PASSWORD_BUF.length) return false;
  return crypto.timingSafeEqual(buf, MASTER_PASSWORD_BUF);
}

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ─── Spotify Auth (Client Credentials for search) ────────────────────────────

let spotifyToken = null;
let spotifyTokenExpiry = 0;

async function getSpotifyToken() {
  if (spotifyToken && Date.now() < spotifyTokenExpiry) {
    return spotifyToken;
  }

  if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
    throw new Error('Spotify credentials not configured. Set SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET.');
  }

  const credentials = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=client_credentials'
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Spotify auth failed (${res.status}): ${text}`);
  }

  const data = await res.json();
  spotifyToken = data.access_token;
  spotifyTokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  console.log('Spotify token acquired/refreshed');
  return spotifyToken;
}

// ─── Spotify OAuth (User Auth for Web Playback SDK) ───────────────────────────

const SPOTIFY_SCOPES = 'streaming user-read-email user-read-private user-modify-playback-state user-read-playback-state playlist-modify-public playlist-modify-private';

// In-memory state store for OAuth CSRF protection (state → expiry)
const oauthStates = new Map();
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function rememberOAuthState(state) {
  oauthStates.set(state, Date.now() + OAUTH_STATE_TTL_MS);
  // Opportunistic cleanup of expired states
  if (oauthStates.size > 100) {
    const now = Date.now();
    for (const [s, expiry] of oauthStates) {
      if (expiry < now) oauthStates.delete(s);
    }
  }
}

function consumeOAuthState(state) {
  if (typeof state !== 'string' || !state) return false;
  const expiry = oauthStates.get(state);
  if (!expiry) return false;
  oauthStates.delete(state);  // one-time use
  return Date.now() < expiry;
}

app.get('/auth/spotify', (req, res) => {
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/spotify/callback`;
  const state = crypto.randomBytes(16).toString('hex');
  rememberOAuthState(state);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: SPOTIFY_CLIENT_ID,
    scope: SPOTIFY_SCOPES,
    redirect_uri: redirectUri,
    state: state,
    show_dialog: 'false'
  });
  res.redirect(`https://accounts.spotify.com/authorize?${params}`);
});

function authResultPage(payload, origin) {
  const payloadJson = JSON.stringify(payload);
  const originJson = JSON.stringify(origin);
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Spotify Auth</title>
<style>body{font-family:system-ui,sans-serif;background:#121212;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;padding:20px}</style>
</head><body><div><h2>${payload.type === 'spotify-auth-success' ? 'Connected!' : 'Auth failed'}</h2><p id="msg">You can close this window.</p></div>
<script>
(function(){
  var payload = ${payloadJson};
  var targetOrigin = ${originJson};
  // Channel 1: localStorage (works cross-window in Brave / strict browsers)
  try { localStorage.setItem('spotify_auth_pending', JSON.stringify(Object.assign({ts: Date.now()}, payload))); } catch(e){}
  // Channel 2: postMessage to opener (works in Chrome/Firefox)
  try { if (window.opener && !window.opener.closed) { window.opener.postMessage(payload, targetOrigin); } } catch(e){}
  // Try to close; if blocked, message stays visible
  setTimeout(function(){ try { window.close(); } catch(e){} }, 150);
  setTimeout(function(){ if (!window.closed) { document.getElementById('msg').textContent = 'Done. You can close this window.'; } }, 600);
})();
</script></body></html>`;
}

app.get('/auth/spotify/callback', async (req, res) => {
  const { code, error, state } = req.query;
  const origin = `${req.protocol}://${req.get('host')}`;

  if (error) {
    return res.send(authResultPage({ type: 'spotify-auth-error', error: String(error) }, origin));
  }

  // CSRF protection: state must match one we issued and is not expired/reused
  if (!consumeOAuthState(state)) {
    return res.send(authResultPage({ type: 'spotify-auth-error', error: 'Invalid or expired state (possible CSRF attempt)' }, origin));
  }

  const redirectUri = `${req.protocol}://${req.get('host')}/auth/spotify/callback`;
  const credentials = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');

  const tokenRes = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri
    })
  });

  if (!tokenRes.ok) {
    return res.send(authResultPage({ type: 'spotify-auth-error', error: 'Token exchange failed' }, origin));
  }

  const data = await tokenRes.json();
  res.send(authResultPage({
    type: 'spotify-auth-success',
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in
  }, origin));
});

app.post('/auth/spotify/refresh', express.json(), async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });

  const credentials = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');

  const tokenRes = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token
    })
  });

  if (!tokenRes.ok) {
    return res.status(401).json({ error: 'Failed to refresh token' });
  }

  const data = await tokenRes.json();
  res.json({
    access_token: data.access_token,
    expires_in: data.expires_in,
    refresh_token: data.refresh_token || refresh_token
  });
});

async function searchSpotify(query) {
  const token = await getSpotifyToken();
  const params = new URLSearchParams({
    q: query,
    type: 'track',
    limit: '10'
  });

  const res = await fetch(`https://api.spotify.com/v1/search?${params}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!res.ok) {
    throw new Error(`Spotify search failed: ${res.status}`);
  }

  const data = await res.json();
  return data.tracks.items.map(track => ({
    trackId: track.id,
    title: track.name,
    artist: track.artists.map(a => a.name).join(', '),
    album: track.album.name,
    albumArt: track.album.images[1]?.url || track.album.images[0]?.url || '',
    duration: formatDuration(track.duration_ms)
  }));
}

function formatDuration(ms) {
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.floor((ms % 60000) / 1000);
  return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

// ─── Persistence ───────────────────────────────────────────────────────────────

function getQuizFilePath(quizId) {
  return path.join(DATA_DIR, `${quizId}.json`);
}

function saveQuiz(quiz) {
  const filePath = getQuizFilePath(quiz.id);
  // Write to a temp file then rename so a crash mid-write can't corrupt the quiz
  const tmpPath = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(quiz, null, 2), 'utf8');
  fs.renameSync(tmpPath, filePath);
}

function loadAllQuizzes() {
  const quizzes = {};
  if (fs.existsSync(DATA_DIR)) {
    const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const data = fs.readFileSync(path.join(DATA_DIR, file), 'utf8');
        const quiz = JSON.parse(data);
        quizzes[quiz.id] = quiz;
      } catch (e) {
        console.error(`Failed to load quiz file ${file}:`, e.message);
      }
    }
  }
  return quizzes;
}

// ─── In-memory state (loaded from disk on startup) ─────────────────────────────

const quizzes = loadAllQuizzes();
console.log(`Loaded ${Object.keys(quizzes).length} quiz(es) from disk.`);

// ─── Static files ──────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));

// ─── Routes ────────────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/quiz/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'quiz.html'));
});

app.get('/quizmaster', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'quizmaster.html'));
});

app.get('/master/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'master.html'));
});

app.get('/screen/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'screen.html'));
});

// QR code PNG of the public join link (the link itself stays primary for mailing)
app.get('/quiz/:id/qr.png', (req, res) => {
  if (!isValidQuizId(req.params.id)) return res.status(400).end();
  const quiz = quizzes[req.params.id];
  if (!quiz) return res.status(404).end();
  const joinUrl = `${req.protocol}://${req.get('host')}/quiz/${req.params.id}`;
  res.type('png');
  QRCode.toFileStream(res, joinUrl, { width: 220, margin: 1 });
});

// ─── Input Validation ──────────────────────────────────────────────────────────

function isValidQuizId(id) {
  return typeof id === 'string' && /^[a-f0-9]{8}$/.test(id);
}

// Spotify track IDs are 22 base62 characters
function isValidTrackId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9]{22}$/.test(id);
}

function cleanText(value, maxLen) {
  return typeof value === 'string' ? value.trim().slice(0, maxLen) : '';
}

// ─── Quiz Features ─────────────────────────────────────────────────────────────

const DEFAULT_FEATURES = {
  qr: true,            // QR code in master lobby
  countdown: true,     // host-triggered silent vote countdown
  countdownSeconds: 30,
  effects: true,       // confetti / flash / vibration on reveal
  voteChart: true,     // vote distribution bars on reveal
  awards: true,        // end-of-quiz awards
  soundboard: true,    // host sound effects on the master page (countdown stays silent)
  playlistExport: true,// export the finished quiz as a Spotify playlist (master only)
  nameThatTune: false  // progressive snippet round: earlier correct guess scores more
};

// Name That Tune tiers: snippet length (s, 0 = full) and points for a correct vote at that tier
const TIER_SECONDS = [3, 8, 0];
const TIER_POINTS = [3, 2, 1];

function sanitizeFeatures(input) {
  const f = { ...DEFAULT_FEATURES };
  if (input && typeof input === 'object') {
    for (const key of ['qr', 'countdown', 'effects', 'voteChart', 'awards', 'soundboard', 'playlistExport', 'nameThatTune']) {
      if (typeof input[key] === 'boolean') f[key] = input[key];
    }
    const secs = parseInt(input.countdownSeconds, 10);
    if (Number.isInteger(secs)) f.countdownSeconds = Math.min(300, Math.max(5, secs));
  }
  return f;
}

// Older persisted quizzes have no features field — they get the defaults
function featuresOf(quiz) {
  return sanitizeFeatures(quiz.features);
}

// ─── Master API (password-protected) ──────────────────────────────────────────

app.post('/api/auth', authLimiter, express.json(), (req, res) => {
  const { password } = req.body;
  if (checkPassword(password)) {
    res.json({ success: true });
  } else {
    const ip = req.ip || req.socket.remoteAddress;
    console.warn(`[AUTH] Failed attempt from ${ip} at ${new Date().toISOString()}`);
    res.status(401).json({ error: 'Wrong password' });
  }
});

app.post('/api/quizzes', express.json(), (req, res) => {
  const { password } = req.body;
  if (!checkPassword(password)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const list = Object.values(quizzes)
    .map(q => ({
      id: q.id,
      name: q.name,
      state: q.state,
      contestants: Object.values(q.contestants || {}).map(c => c.username),
      songCount: (q.queue || []).length,
      createdAt: q.createdAt
    }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ quizzes: list });
});

app.post('/api/quiz/:id', express.json(), (req, res) => {
  const { password } = req.body;
  if (!checkPassword(password)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!isValidQuizId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid quiz ID' });
  }
  const quiz = quizzes[req.params.id];
  if (!quiz) return res.status(404).json({ error: 'Quiz not found' });

  const songs = (quiz.queue || []).map(s => ({
    title: s.title,
    artist: s.artist,
    albumArt: s.albumArt,
    trackId: s.trackId,
    addedBy: ownersLabel(s)
  }));

  res.json({
    id: quiz.id,
    name: quiz.name,
    state: quiz.state,
    createdAt: quiz.createdAt,
    contestants: Object.values(quiz.contestants || {}).map(c => c.username),
    songs,
    scores: calculateScores(quiz)
  });
});

app.delete('/api/quiz/:id', express.json(), (req, res) => {
  const { password } = req.body;
  if (!checkPassword(password)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!isValidQuizId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid quiz ID' });
  }
  const quiz = quizzes[req.params.id];
  if (!quiz) return res.status(404).json({ error: 'Quiz not found' });

  delete quizzes[req.params.id];
  const filePath = getQuizFilePath(req.params.id);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  res.json({ success: true });
});

// ─── Countdown Timers (in-memory, per quiz) ───────────────────────────────────

const countdownTimers = new Map(); // quizId → Timeout

function clearCountdown(quizId) {
  const timer = countdownTimers.get(quizId);
  if (timer) {
    clearTimeout(timer);
    countdownTimers.delete(quizId);
  }
}

// Single reveal path used by manual reveal, all-voted auto-reveal and countdown expiry
// Pure builder for an answer-revealed payload (used by reveal + screen rejoin)
function buildRevealPayload(quiz, idx) {
  const song = quiz.queue[idx];
  if (!song) return null;
  const songVotes = quiz.votes[idx] || {};
  const results = {};
  const distribution = {};
  for (const [voter, votedFor] of Object.entries(songVotes)) {
    results[voter] = { votedFor, correct: ownersOf(song).includes(votedFor) };
    distribution[votedFor] = (distribution[votedFor] || 0) + 1;
  }
  return {
    addedBy: ownersLabel(song),
    title: song.title,
    artist: song.artist,
    trackId: song.trackId,
    albumArt: song.albumArt,
    votes: results,
    distribution
  };
}

function revealCurrentSong(quizId, quiz) {
  const currentSong = quiz.queue[quiz.currentIndex];
  if (!currentSong) return null;

  clearCountdown(quizId);
  if (!quiz.revealedIndices) quiz.revealedIndices = [];
  if (!quiz.revealedIndices.includes(quiz.currentIndex)) {
    quiz.revealedIndices.push(quiz.currentIndex);
    saveQuiz(quiz);
  }

  const payload = buildRevealPayload(quiz, quiz.currentIndex);
  io.to(`quiz-${quizId}`).emit('answer-revealed', payload);
  return payload;
}

function calculateAwards(quiz) {
  // Per owner: how many votes their songs tricked vs. how often they were seen through
  const fooled = {};
  const caught = {};
  for (const [idx, songVotes] of Object.entries(quiz.votes || {})) {
    const song = (quiz.queue || [])[parseInt(idx)];
    if (!song) continue;
    const owners = ownersOf(song);
    for (const votedFor of Object.values(songVotes)) {
      const correct = owners.includes(votedFor);
      for (const owner of owners) {
        if (correct) caught[owner] = (caught[owner] || 0) + 1;
        else fooled[owner] = (fooled[owner] || 0) + 1;
      }
    }
  }
  const top = (counts) => {
    const max = Math.max(...Object.values(counts));
    return [Object.keys(counts).filter(k => counts[k] === max).join(' & '), max];
  };
  const awards = [];
  if (Object.keys(fooled).length > 0) {
    const [names, n] = top(fooled);
    awards.push({ emoji: '\u{1F3AD}', title: 'Master of Deception', username: names, detail: `tricked ${n} vote${n === 1 ? '' : 's'}` });
  }
  if (Object.keys(caught).length > 0) {
    const [names, n] = top(caught);
    awards.push({ emoji: '\u{1F4D6}', title: 'Open Book', username: names, detail: `guessed right ${n} time${n === 1 ? '' : 's'} by the others` });
  }
  return awards;
}

// Per-socket sliding-window rate limiter; returns true if the action is allowed
function allowAction(socket, key, max, windowMs) {
  const now = Date.now();
  if (!socket._rl) socket._rl = {};
  const recent = (socket._rl[key] || []).filter(t => now - t < windowMs);
  if (recent.length >= max) { socket._rl[key] = recent; return false; }
  recent.push(now);
  socket._rl[key] = recent;
  return true;
}

const ALLOWED_REACTIONS = new Set(['\u{1F525}', '\u{1F602}', '\u{1F631}', '\u{1F44F}', '❤️', '\u{1F389}']);

// ─── Socket.IO ─────────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
  console.log(`Socket connected: ${socket.id}`);

  // ─── Create Quiz ───────────────────────────────────────────────────────────
  socket.on('create-quiz', ({ quizName, songsPerPerson, password, features }, callback) => {
    if (!checkPassword(password)) return callback({ error: 'Unauthorized' });
    const quizId = uuidv4().slice(0, 8);
    const quiz = {
      id: quizId,
      name: cleanText(quizName, 100) || 'Music Quiz',
      songsPerPerson: Number.isInteger(songsPerPerson) && songsPerPerson >= 1 && songsPerPerson <= 20
        ? songsPerPerson : 3,
      features: sanitizeFeatures(features),
      state: 'lobby', // lobby | playing | finished
      contestants: {},
      queue: [],
      currentIndex: -1,
      votes: {},
      masterId: socket.id,
      createdAt: new Date().toISOString()
    };
    quizzes[quizId] = quiz;
    saveQuiz(quiz);
    socket.join(`quiz-${quizId}`);
    socket.quizId = quizId;
    socket.isMaster = true;
    callback({ quizId });
    console.log(`Quiz created: ${quizId} - "${quiz.name}"`);
  });

  // ─── Rejoin as Master ──────────────────────────────────────────────────────
  socket.on('rejoin-master', ({ quizId, password }, callback) => {
    if (!checkPassword(password)) return callback({ error: 'Unauthorized' });
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    quiz.masterId = socket.id;
    socket.join(`quiz-${quizId}`);
    socket.quizId = quizId;
    socket.isMaster = true;
    saveQuiz(quiz);
    // Master view: addedBy as display label, owners as array for vote-count math
    const masterQuiz = {
      ...quiz,
      features: featuresOf(quiz),
      queue: (quiz.queue || []).map(s => ({ ...s, addedBy: ownersLabel(s), owners: ownersOf(s) }))
    };
    callback({
      quiz: masterQuiz,
      scores: quiz.state === 'finished' ? calculateScores(quiz) : undefined,
      awards: quiz.state === 'finished' && featuresOf(quiz).awards ? calculateAwards(quiz) : undefined
    });
  });

  // ─── Join Quiz ─────────────────────────────────────────────────────────────
  socket.on('join-quiz', ({ quizId, username }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (!username || username.trim() === '') return callback({ error: 'Username required' });

    const trimmed = username.trim();

    const existingEntry = Object.entries(quiz.contestants).find(
      ([, c]) => c.username === trimmed
    );

    // If quiz already started, only allow rejoining as existing contestant
    if (quiz.state !== 'lobby') {
      if (!existingEntry) {
        return callback({ error: 'Quiz already started' });
      }
      // Rejoin: update socket id for existing contestant
      const [oldSocketId] = existingEntry;
      const contestantData = quiz.contestants[oldSocketId];
      delete quiz.contestants[oldSocketId];
      quiz.contestants[socket.id] = contestantData;
      socket.join(`quiz-${quizId}`);
      socket.quizId = quizId;
      socket.username = trimmed;
      saveQuiz(quiz);
      // Include user-specific state so client can fully restore
      const myVote = quiz.votes[quiz.currentIndex]?.[trimmed] || null;
      const myScores = quiz.state === 'finished' ? calculateScores(quiz) : null;
      const allSongs = quiz.state === 'finished'
        ? quiz.queue.map(s => ({ title: s.title, artist: s.artist, albumArt: s.albumArt, trackId: s.trackId, addedBy: ownersLabel(s) }))
        : null;
      const myAwards = quiz.state === 'finished' && featuresOf(quiz).awards ? calculateAwards(quiz) : null;
      callback({ quiz: sanitizeQuizForContestant(quiz), mySongs: contestantData.songs, myVote, scores: myScores, songs: allSongs, awards: myAwards });
      return;
    }

    if (existingEntry) {
      const [oldSocketId] = existingEntry;
      const songs = quiz.contestants[oldSocketId].songs;
      delete quiz.contestants[oldSocketId];
      quiz.contestants[socket.id] = { username: trimmed, songs };
    } else {
      // Length cap applies to new joins only, so existing names can always rejoin
      if (trimmed.length > 40) {
        return callback({ error: 'Name too long (max 40 characters)' });
      }
      quiz.contestants[socket.id] = { username: trimmed, songs: [] };
    }

    socket.join(`quiz-${quizId}`);
    socket.quizId = quizId;
    socket.username = trimmed;
    saveQuiz(quiz);

    const contestant = quiz.contestants[socket.id];
    callback({ quiz: sanitizeQuizForContestant(quiz), mySongs: contestant.songs });
    // Only broadcast join event for new contestants, not rejoins
    if (!existingEntry) {
      io.to(`quiz-${quizId}`).emit('contestant-joined', {
        username: trimmed,
        contestants: Object.values(quiz.contestants).map(c => ({
          username: c.username,
          songCount: c.songs.length
        }))
      });
    }
    console.log(`${trimmed} joined quiz ${quizId}`);
  });

  // ─── Spotify Search ────────────────────────────────────────────────────────
  socket.on('search-spotify', async ({ query }, callback) => {
    callback = typeof callback === 'function' ? callback : () => {};
    // Protect the shared Spotify API quota from a single spamming contestant
    if (!allowAction(socket, 'search', 8, 5000)) {
      return callback({ tracks: [], error: 'Slow down — too many searches, try again in a moment' });
    }
    try {
      const tracks = await searchSpotify(query);
      callback({ tracks });
    } catch (err) {
      console.error('Spotify search error:', err.message);
      callback({ tracks: [], error: err.message });
    }
  });

  // ─── Emoji Reaction (floats on the TV screen) ──────────────────────────────
  socket.on('react', ({ quizId, emoji }) => {
    const quiz = quizzes[quizId];
    if (!quiz || socket.quizId !== quizId) return;
    if (!ALLOWED_REACTIONS.has(emoji)) return;
    if (!allowAction(socket, 'react', 6, 3000)) return;
    io.to(`quiz-${quizId}`).emit('reaction', { emoji });
  });

  // ─── Add Song ──────────────────────────────────────────────────────────────
  socket.on('add-song', ({ quizId, song }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (quiz.state !== 'lobby') return callback({ error: 'Quiz already started' });

    const contestant = quiz.contestants[socket.id];
    if (!contestant) return callback({ error: 'Not a contestant' });
    if (contestant.songs.length >= quiz.songsPerPerson) {
      return callback({ error: `Maximum ${quiz.songsPerPerson} songs allowed` });
    }

    // Never trust client-supplied song data: validate id, cap text, https-only art
    if (!song || !isValidTrackId(song.trackId)) {
      return callback({ error: 'Invalid song' });
    }
    const title = cleanText(song.title, 200);
    const artist = cleanText(song.artist, 200);
    const albumArt = /^https:\/\//.test(song.albumArt || '') ? String(song.albumArt).slice(0, 300) : '';
    if (!title) return callback({ error: 'Invalid song' });

    contestant.songs.push({
      trackId: song.trackId,
      title,
      artist,
      albumArt
    });
    saveQuiz(quiz);

    callback({ songs: contestant.songs });
    io.to(`quiz-${quizId}`).emit('songs-updated', {
      contestants: Object.values(quiz.contestants).map(c => ({
        username: c.username,
        songCount: c.songs.length
      }))
    });
  });

  // ─── Remove Song ───────────────────────────────────────────────────────────
  socket.on('remove-song', ({ quizId, index }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });

    const contestant = quiz.contestants[socket.id];
    if (!contestant) return callback({ error: 'Not a contestant' });

    if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index >= contestant.songs.length) {
      return callback({ error: 'Invalid song index' });
    }

    contestant.songs.splice(index, 1);
    saveQuiz(quiz);

    callback({ songs: contestant.songs });
    io.to(`quiz-${quizId}`).emit('songs-updated', {
      contestants: Object.values(quiz.contestants).map(c => ({
        username: c.username,
        songCount: c.songs.length
      }))
    });
  });

  // ─── Start Quiz ────────────────────────────────────────────────────────────
  socket.on('start-quiz', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (socket.id !== quiz.masterId) return callback({ error: 'Not the quiz master' });

    const allSongs = [];
    for (const [, contestant] of Object.entries(quiz.contestants)) {
      for (const song of contestant.songs) {
        allSongs.push({ ...song, addedBy: contestant.username });
      }
    }

    if (allSongs.length === 0) return callback({ error: 'No songs added yet' });

    // Merge duplicate tracks: if several contestants picked the same song it
    // becomes one queue entry owned by all of them
    const byTrack = new Map();
    for (const song of allSongs) {
      const existing = byTrack.get(song.trackId);
      if (existing) {
        if (!existing.addedBy.includes(song.addedBy)) existing.addedBy.push(song.addedBy);
      } else {
        byTrack.set(song.trackId, { ...song, addedBy: [song.addedBy] });
      }
    }
    const queue = [...byTrack.values()];

    // Fisher-Yates shuffle
    for (let i = queue.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [queue[i], queue[j]] = [queue[j], queue[i]];
    }

    quiz.queue = queue;
    quiz.state = 'playing';
    quiz.currentIndex = 0;
    quiz.votes = {};
    quiz.voteTiers = {};
    quiz.currentTier = 1;
    saveQuiz(quiz);

    callback({ success: true });
    const firstSong = quiz.queue[0];
    const eligibleVoterCount = Object.values(quiz.contestants)
      .filter(c => !ownersOf(firstSong).includes(c.username)).length;
    // Send full song info to master only
    io.to(quiz.masterId).emit('quiz-started', {
      totalSongs: quiz.queue.length,
      currentIndex: 0,
      currentSong: sanitizeSong(firstSong),
      contestants: Object.values(quiz.contestants).map(c => c.username),
      eligibleVoterCount
    });
    // Send stripped song info to contestants
    socket.to(`quiz-${quizId}`).emit('quiz-started', {
      totalSongs: quiz.queue.length,
      currentIndex: 0,
      currentSong: sanitizeSongForContestant(firstSong),
      contestants: Object.values(quiz.contestants).map(c => c.username),
      eligibleVoterCount
    });
    console.log(`Quiz ${quizId} started with ${allSongs.length} songs`);
  });

  // ─── Previous Song ──────────────────────────────────────────────────────────
  socket.on('prev-song', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (socket.id !== quiz.masterId) return callback({ error: 'Not the quiz master' });
    if (quiz.currentIndex <= 0) return callback({ error: 'Already at first song' });

    clearCountdown(quizId);
    quiz.currentIndex--;
    quiz.currentTier = 1;
    saveQuiz(quiz);
    const song = quiz.queue[quiz.currentIndex];
    const eligibleVoterCount = Object.values(quiz.contestants)
      .filter(c => !ownersOf(song).includes(c.username)).length;
    // Full info to master
    io.to(quiz.masterId).emit('prev-song', {
      currentIndex: quiz.currentIndex,
      currentSong: sanitizeSong(song),
      totalSongs: quiz.queue.length,
      eligibleVoterCount
    });
    // Stripped info to contestants
    socket.to(`quiz-${quizId}`).emit('prev-song', {
      currentIndex: quiz.currentIndex,
      currentSong: sanitizeSongForContestant(song),
      totalSongs: quiz.queue.length,
      eligibleVoterCount
    });
    callback({ currentIndex: quiz.currentIndex });
  });

  // ─── Next Song ─────────────────────────────────────────────────────────────
  socket.on('next-song', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (socket.id !== quiz.masterId) return callback({ error: 'Not the quiz master' });

    clearCountdown(quizId);
    quiz.currentIndex++;
    quiz.currentTier = 1;

    if (quiz.currentIndex >= quiz.queue.length) {
      quiz.state = 'finished';
      saveQuiz(quiz);
      const scores = calculateScores(quiz);
      const songs = quiz.queue.map(s => ({
        title: s.title,
        artist: s.artist,
        albumArt: s.albumArt,
        trackId: s.trackId,
        addedBy: ownersLabel(s)
      }));
      const awards = featuresOf(quiz).awards ? calculateAwards(quiz) : [];
      io.to(`quiz-${quizId}`).emit('quiz-finished', { scores, songs, awards });
      callback({ finished: true, scores });
    } else {
      saveQuiz(quiz);
      const song = quiz.queue[quiz.currentIndex];
      const prevSong = quiz.queue[quiz.currentIndex - 1];
      const eligibleVoterCount = Object.values(quiz.contestants)
        .filter(c => !ownersOf(song).includes(c.username)).length;
      const previousSong = prevSong
        ? { title: prevSong.title, artist: prevSong.artist, albumArt: prevSong.albumArt, trackId: prevSong.trackId, addedBy: ownersLabel(prevSong) }
        : null;
      // Full info to master (include previous song for history)
      io.to(quiz.masterId).emit('next-song', {
        currentIndex: quiz.currentIndex,
        currentSong: sanitizeSong(song),
        totalSongs: quiz.queue.length,
        previousSong,
        eligibleVoterCount
      });
      // Stripped info to contestants
      socket.to(`quiz-${quizId}`).emit('next-song', {
        currentIndex: quiz.currentIndex,
        currentSong: sanitizeSongForContestant(song),
        totalSongs: quiz.queue.length,
        previousSong,
        eligibleVoterCount
      });
      callback({ finished: false, currentIndex: quiz.currentIndex });
    }
  });

  // ─── Reveal Answer ─────────────────────────────────────────────────────────
  socket.on('reveal-answer', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (socket.id !== quiz.masterId) return callback({ error: 'Not the quiz master' });

    const payload = revealCurrentSong(quizId, quiz);
    if (!payload) return callback({ error: 'No current song' });
    callback({ addedBy: payload.addedBy, votes: payload.votes });
  });

  // ─── Start Countdown (silent, visual only) ─────────────────────────────────
  socket.on('start-countdown', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (socket.id !== quiz.masterId) return callback({ error: 'Not the quiz master' });
    if (quiz.state !== 'playing') return callback({ error: 'Quiz not in progress' });
    const features = featuresOf(quiz);
    if (!features.countdown) return callback({ error: 'Countdown is disabled for this quiz' });
    if (quiz.revealedIndices && quiz.revealedIndices.includes(quiz.currentIndex)) {
      return callback({ error: 'Answer already revealed' });
    }

    const seconds = features.countdownSeconds;
    const songIndex = quiz.currentIndex;
    clearCountdown(quizId);
    countdownTimers.set(quizId, setTimeout(() => {
      countdownTimers.delete(quizId);
      const q = quizzes[quizId];
      // Only reveal if the quiz is still on the same unrevealed song
      if (!q || q.state !== 'playing' || q.currentIndex !== songIndex) return;
      if (q.revealedIndices && q.revealedIndices.includes(songIndex)) return;
      revealCurrentSong(quizId, q);
    }, seconds * 1000));

    io.to(`quiz-${quizId}`).emit('countdown-started', {
      seconds,
      endsAt: Date.now() + seconds * 1000
    });
    callback({ success: true });
  });

  // ─── Name That Tune: advance the snippet tier (master only) ────────────────
  socket.on('set-tier', ({ quizId, tier }, callback) => {
    callback = typeof callback === 'function' ? callback : () => {};
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (socket.id !== quiz.masterId) return callback({ error: 'Not the quiz master' });
    if (!featuresOf(quiz).nameThatTune) return callback({ error: 'Not in Name That Tune mode' });
    const t = Math.max(1, Math.min(TIER_POINTS.length, parseInt(tier, 10) || 1));
    quiz.currentTier = t;
    saveQuiz(quiz);
    io.to(`quiz-${quizId}`).emit('tier-changed', {
      tier: t,
      points: TIER_POINTS[t - 1],
      snippetSeconds: TIER_SECONDS[t - 1]
    });
    callback({ success: true });
  });

  // ─── Vote ──────────────────────────────────────────────────────────────────
  socket.on('vote', ({ quizId, votedFor }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (quiz.state !== 'playing') return callback({ error: 'Quiz not in progress' });

    const contestant = quiz.contestants[socket.id];
    if (!contestant) return callback({ error: 'Not a contestant' });

    const currentSong = quiz.queue[quiz.currentIndex];
    if (ownersOf(currentSong).includes(contestant.username)) {
      return callback({ error: 'You cannot vote on your own song' });
    }

    // Voting closes once the answer is revealed (manual or auto)
    if (quiz.revealedIndices && quiz.revealedIndices.includes(quiz.currentIndex)) {
      return callback({ error: 'Voting is closed — the answer was already revealed' });
    }

    const validTargets = Object.values(quiz.contestants).map(c => c.username);
    if (!validTargets.includes(votedFor)) {
      return callback({ error: 'Invalid vote target' });
    }
    const idx = quiz.currentIndex;
    if (!quiz.votes[idx]) quiz.votes[idx] = {};
    quiz.votes[idx][contestant.username] = votedFor;
    // Name That Tune: stamp the snippet tier this vote was locked in at
    if (featuresOf(quiz).nameThatTune) {
      if (!quiz.voteTiers) quiz.voteTiers = {};
      if (!quiz.voteTiers[idx]) quiz.voteTiers[idx] = {};
      quiz.voteTiers[idx][contestant.username] = quiz.currentTier || 1;
    }
    saveQuiz(quiz);

    callback({ success: true });

    const eligibleVoters = Object.values(quiz.contestants)
      .filter(c => !ownersOf(currentSong).includes(c.username));
    const currentVotes = quiz.votes[idx];
    const voteCount = Object.keys(currentVotes).length;

    io.to(`quiz-${quizId}`).emit('vote-update', {
      voteCount,
      totalContestants: eligibleVoters.length
    });

    const allVoted = eligibleVoters.length > 0 &&
      eligibleVoters.every(c => currentVotes[c.username] !== undefined);

    if (allVoted) {
      revealCurrentSong(quizId, quiz);
    }
  });

  // ─── Get Quiz State ────────────────────────────────────────────────────────
  socket.on('get-quiz-state', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    callback({ quiz: sanitizeQuizForContestant(quiz) });
  });

  // ─── Join as TV Screen (read-only spectator; gets the contestant-safe stream) ──
  socket.on('join-screen', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    socket.join(`quiz-${quizId}`);
    socket.quizId = quizId;

    const res = {
      quiz: sanitizeQuizForContestant(quiz),
      contestants: Object.values(quiz.contestants).map(c => ({
        username: c.username,
        songCount: c.songs.length
      }))
    };

    if (quiz.state === 'finished') {
      res.scores = calculateScores(quiz);
      res.songs = quiz.queue.map(s => ({
        title: s.title, artist: s.artist, albumArt: s.albumArt, trackId: s.trackId, addedBy: ownersLabel(s)
      }));
      res.awards = featuresOf(quiz).awards ? calculateAwards(quiz) : [];
    } else if (quiz.state === 'playing') {
      const idx = quiz.currentIndex;
      const cur = quiz.queue[idx];
      const eligible = cur
        ? Object.values(quiz.contestants).filter(c => !ownersOf(cur).includes(c.username)).length
        : 0;
      res.totalEligible = eligible;
      if (quiz.revealedIndices && quiz.revealedIndices.includes(idx)) {
        res.reveal = buildRevealPayload(quiz, idx);
      } else {
        res.voteCount = Object.keys(quiz.votes[idx] || {}).length;
      }
    }
    callback(res);
  });

  // ─── Disconnect ────────────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    console.log(`Socket disconnected: ${socket.id}`);
  });
});

// ─── Helpers ───────────────────────────────────────────────────────────────────

// A queue entry's addedBy is an array of owner names (several contestants can
// pick the same track). Older persisted quizzes stored a plain string.
function ownersOf(song) {
  if (Array.isArray(song.addedBy)) return song.addedBy;
  return song.addedBy ? [song.addedBy] : [];
}

function ownersLabel(song) {
  return ownersOf(song).join(' & ');
}

function sanitizeSong(song) {
  return {
    trackId: song.trackId,
    title: song.title,
    artist: song.artist,
    albumArt: song.albumArt
  };
}

function sanitizeSongForContestant(song) {
  return {
    trackId: song.trackId
  };
}

function sanitizeQuizForContestant(quiz) {
  return {
    id: quiz.id,
    name: quiz.name,
    songsPerPerson: quiz.songsPerPerson,
    features: featuresOf(quiz),
    state: quiz.state,
    contestants: Object.values(quiz.contestants).map(c => ({
      username: c.username,
      songCount: c.songs.length
    })),
    currentIndex: quiz.currentIndex,
    totalSongs: quiz.queue.length,
    currentSong: quiz.state === 'playing' && quiz.queue[quiz.currentIndex]
      ? sanitizeSongForContestant(quiz.queue[quiz.currentIndex])
      : null
  };
}

function calculateScores(quiz) {
  const nameThatTune = featuresOf(quiz).nameThatTune;
  // Points for a correct vote: classic = 1; Name That Tune = points for the tier it was locked at
  const pointsFor = (idx, voter) => {
    if (!nameThatTune) return 1;
    const tier = (quiz.voteTiers && quiz.voteTiers[idx] && quiz.voteTiers[idx][voter]) || TIER_POINTS.length;
    return TIER_POINTS[tier - 1] || 1;
  };
  const scores = {};
  for (const c of Object.values(quiz.contestants || {})) {
    scores[c.username] = 0;
  }
  for (const [idx, songVotes] of Object.entries(quiz.votes || {})) {
    const song = (quiz.queue || [])[parseInt(idx)];
    if (!song) continue;
    for (const [voter, votedFor] of Object.entries(songVotes)) {
      if (ownersOf(song).includes(votedFor)) {
        scores[voter] = (scores[voter] || 0) + pointsFor(idx, voter);
      }
    }
  }
  return Object.entries(scores)
    .map(([username, score]) => ({ username, score }))
    .sort((a, b) => b.score - a.score);
}

// ─── Start Server ──────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`OnlyMIP MusicQuiz server running on http://localhost:${PORT}`);
  if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
    console.warn('WARNING: SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET not set. Search will not work.');
    console.warn('Get credentials at: https://developer.spotify.com/dashboard');
  }
});
