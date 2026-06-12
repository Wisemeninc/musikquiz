const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
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

const SPOTIFY_SCOPES = 'streaming user-read-email user-read-private user-modify-playback-state user-read-playback-state';

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
  fs.writeFileSync(filePath, JSON.stringify(quiz, null, 2), 'utf8');
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

// ─── Input Validation ──────────────────────────────────────────────────────────

function isValidQuizId(id) {
  return typeof id === 'string' && /^[a-f0-9]{8}$/.test(id);
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
    addedBy: s.addedBy
  }));

  const scores = {};
  for (const c of Object.values(quiz.contestants || {})) {
    scores[c.username] = 0;
  }
  for (const [idx, songVotes] of Object.entries(quiz.votes || {})) {
    const song = quiz.queue[parseInt(idx)];
    if (!song) continue;
    for (const [, votedFor] of Object.entries(songVotes)) {
      if (votedFor === song.addedBy) {
        scores[votedFor] = (scores[votedFor] || 0) + 1;
      }
    }
  }

  res.json({
    id: quiz.id,
    name: quiz.name,
    state: quiz.state,
    createdAt: quiz.createdAt,
    contestants: Object.values(quiz.contestants || {}).map(c => c.username),
    songs,
    scores: Object.entries(scores)
      .map(([username, score]) => ({ username, score }))
      .sort((a, b) => b.score - a.score)
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

// ─── Socket.IO ─────────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
  console.log(`Socket connected: ${socket.id}`);

  // ─── Create Quiz ───────────────────────────────────────────────────────────
  socket.on('create-quiz', ({ quizName, songsPerPerson, password }, callback) => {
    if (!checkPassword(password)) return callback({ error: 'Unauthorized' });
    const quizId = uuidv4().slice(0, 8);
    const quiz = {
      id: quizId,
      name: quizName || 'Music Quiz',
      songsPerPerson: songsPerPerson || 3,
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
    callback({ quiz });
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
        ? quiz.queue.map(s => ({ title: s.title, artist: s.artist, albumArt: s.albumArt, trackId: s.trackId, addedBy: s.addedBy }))
        : null;
      callback({ quiz: sanitizeQuizForContestant(quiz), mySongs: contestantData.songs, myVote, scores: myScores, songs: allSongs });
      return;
    }

    if (existingEntry) {
      const [oldSocketId] = existingEntry;
      const songs = quiz.contestants[oldSocketId].songs;
      delete quiz.contestants[oldSocketId];
      quiz.contestants[socket.id] = { username: trimmed, songs };
    } else {
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
        contestants: Object.values(quiz.contestants).map(c => c.username)
      });
    }
    console.log(`${trimmed} joined quiz ${quizId}`);
  });

  // ─── Spotify Search ────────────────────────────────────────────────────────
  socket.on('search-spotify', async ({ query }, callback) => {
    try {
      const tracks = await searchSpotify(query);
      callback({ tracks });
    } catch (err) {
      console.error('Spotify search error:', err.message);
      callback({ tracks: [], error: err.message });
    }
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

    contestant.songs.push({
      trackId: song.trackId,
      title: song.title,
      artist: song.artist,
      albumArt: song.albumArt
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

    // Fisher-Yates shuffle
    for (let i = allSongs.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [allSongs[i], allSongs[j]] = [allSongs[j], allSongs[i]];
    }

    quiz.queue = allSongs;
    quiz.state = 'playing';
    quiz.currentIndex = 0;
    quiz.votes = {};
    saveQuiz(quiz);

    callback({ success: true });
    const firstSong = quiz.queue[0];
    const eligibleVoterCount = Object.values(quiz.contestants)
      .filter(c => c.username !== firstSong.addedBy).length;
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

    quiz.currentIndex--;
    saveQuiz(quiz);
    const song = quiz.queue[quiz.currentIndex];
    const eligibleVoterCount = Object.values(quiz.contestants)
      .filter(c => c.username !== song.addedBy).length;
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

    quiz.currentIndex++;

    if (quiz.currentIndex >= quiz.queue.length) {
      quiz.state = 'finished';
      saveQuiz(quiz);
      const scores = calculateScores(quiz);
      const songs = quiz.queue.map(s => ({
        title: s.title,
        artist: s.artist,
        albumArt: s.albumArt,
        trackId: s.trackId,
        addedBy: s.addedBy
      }));
      io.to(`quiz-${quizId}`).emit('quiz-finished', { scores, songs });
      callback({ finished: true, scores });
    } else {
      saveQuiz(quiz);
      const song = quiz.queue[quiz.currentIndex];
      const prevSong = quiz.queue[quiz.currentIndex - 1];
      const eligibleVoterCount = Object.values(quiz.contestants)
        .filter(c => c.username !== song.addedBy).length;
      // Full info to master (include previous song for history)
      io.to(quiz.masterId).emit('next-song', {
        currentIndex: quiz.currentIndex,
        currentSong: sanitizeSong(song),
        totalSongs: quiz.queue.length,
        previousSong: prevSong ? { title: prevSong.title, artist: prevSong.artist, albumArt: prevSong.albumArt, trackId: prevSong.trackId, addedBy: prevSong.addedBy } : null,
        eligibleVoterCount
      });
      // Stripped info to contestants
      socket.to(`quiz-${quizId}`).emit('next-song', {
        currentIndex: quiz.currentIndex,
        currentSong: sanitizeSongForContestant(song),
        totalSongs: quiz.queue.length,
        previousSong: prevSong ? { title: prevSong.title, artist: prevSong.artist, albumArt: prevSong.albumArt, trackId: prevSong.trackId, addedBy: prevSong.addedBy } : null,
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

    const currentSong = quiz.queue[quiz.currentIndex];
    if (!currentSong) return callback({ error: 'No current song' });

    // Track revealed indices
    if (!quiz.revealedIndices) quiz.revealedIndices = [];
    if (!quiz.revealedIndices.includes(quiz.currentIndex)) {
      quiz.revealedIndices.push(quiz.currentIndex);
      saveQuiz(quiz);
    }

    const songVotes = quiz.votes[quiz.currentIndex] || {};
    const results = {};
    for (const [voter, votedFor] of Object.entries(songVotes)) {
      results[voter] = {
        votedFor,
        correct: votedFor === currentSong.addedBy
      };
    }

    io.to(`quiz-${quizId}`).emit('answer-revealed', {
      addedBy: currentSong.addedBy,
      title: currentSong.title,
      artist: currentSong.artist,
      trackId: currentSong.trackId,
      albumArt: currentSong.albumArt,
      votes: results
    });
    callback({ addedBy: currentSong.addedBy, votes: results });
  });

  // ─── Vote ──────────────────────────────────────────────────────────────────
  socket.on('vote', ({ quizId, votedFor }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    if (quiz.state !== 'playing') return callback({ error: 'Quiz not in progress' });

    const contestant = quiz.contestants[socket.id];
    if (!contestant) return callback({ error: 'Not a contestant' });

    const currentSong = quiz.queue[quiz.currentIndex];
    if (currentSong.addedBy === contestant.username) {
      return callback({ error: 'You cannot vote on your own song' });
    }

    const validTargets = Object.values(quiz.contestants).map(c => c.username);
    if (!validTargets.includes(votedFor)) {
      return callback({ error: 'Invalid vote target' });
    }
    const idx = quiz.currentIndex;
    if (!quiz.votes[idx]) quiz.votes[idx] = {};
    quiz.votes[idx][contestant.username] = votedFor;
    saveQuiz(quiz);

    callback({ success: true });

    const eligibleVoters = Object.values(quiz.contestants)
      .filter(c => c.username !== currentSong.addedBy);
    const currentVotes = quiz.votes[idx];
    const voteCount = Object.keys(currentVotes).length;

    io.to(`quiz-${quizId}`).emit('vote-update', {
      voteCount,
      totalContestants: eligibleVoters.length
    });

    const allVoted = eligibleVoters.length > 0 &&
      eligibleVoters.every(c => currentVotes[c.username] !== undefined);

    if (allVoted) {
      if (!quiz.revealedIndices) quiz.revealedIndices = [];
      if (!quiz.revealedIndices.includes(idx)) {
        quiz.revealedIndices.push(idx);
        saveQuiz(quiz);
      }
      const results = {};
      for (const [voter, voted] of Object.entries(currentVotes)) {
        results[voter] = { votedFor: voted, correct: voted === currentSong.addedBy };
      }
      io.to(`quiz-${quizId}`).emit('answer-revealed', {
        addedBy: currentSong.addedBy,
        title: currentSong.title,
        artist: currentSong.artist,
        trackId: currentSong.trackId,
        albumArt: currentSong.albumArt,
        votes: results
      });
    }
  });

  // ─── Get Quiz State ────────────────────────────────────────────────────────
  socket.on('get-quiz-state', ({ quizId }, callback) => {
    const quiz = quizzes[quizId];
    if (!quiz) return callback({ error: 'Quiz not found' });
    callback({ quiz: sanitizeQuizForContestant(quiz) });
  });

  // ─── Disconnect ────────────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    console.log(`Socket disconnected: ${socket.id}`);
  });
});

// ─── Helpers ───────────────────────────────────────────────────────────────────

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
  const scores = {};
  for (const c of Object.values(quiz.contestants)) {
    scores[c.username] = 0;
  }
  for (const [idx, songVotes] of Object.entries(quiz.votes)) {
    const song = quiz.queue[parseInt(idx)];
    if (!song) continue;
    for (const [voter, votedFor] of Object.entries(songVotes)) {
      if (votedFor === song.addedBy) {
        scores[voter] = (scores[voter] || 0) + 1;
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
