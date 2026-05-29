# MusikQuiz

A music quiz web app where contestants add Spotify songs and others guess who picked each song.

## Features

- Real-time multiplayer via Socket.IO
- Spotify Web Playback SDK for full track playback (Premium required)
- Quiz master controls playback, contestants vote on their phones
- Song info hidden from contestants until the answer is revealed
- Revealed answers link directly to Spotify
- Previous songs list for contestants during the game
- Password-protected quiz master panel
- Quiz history to revisit old quizzes
- Traefik reverse proxy with automatic Let's Encrypt TLS

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/Wisemeninc/musikquiz.git
   cd musikquiz
   ```

2. Copy the example env file and fill in your values:
   ```bash
   cp .env.example .env
   ```

3. Get Spotify credentials at https://developer.spotify.com/dashboard
   - Create an app
   - Add `https://your-domain/auth/spotify/callback` as a Redirect URI

4. Run with Docker:
   ```bash
   docker compose up -d --build
   ```

   Or without Docker:
   ```bash
   npm install
   node server.js
   ```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `DATA_DIR` | Quiz data storage path | `./data` |
| `DOMAIN` | Domain for Traefik routing | — |
| `MASTER_PASSWORD` | Password to access quiz master | `quiz123` |
| `SPOTIFY_CLIENT_ID` | Spotify app client ID | — |
| `SPOTIFY_CLIENT_SECRET` | Spotify app client secret | — |

## How It Works

1. **Quiz Master** creates a quiz and shares the link with contestants
2. **Contestants** join and add their songs (hidden from others)
3. **Quiz Master** starts the quiz — songs play in shuffled order via Spotify SDK
4. **Contestants** vote on who they think picked each song
5. **Quiz Master** reveals the answer (song title + who added it)
6. Final scoreboard shows who guessed the most correctly

## Tech Stack

- Node.js + Express
- Socket.IO for real-time communication
- Spotify Web Playback SDK + Web API
- Vanilla JS frontend
- Docker + Traefik for deployment
