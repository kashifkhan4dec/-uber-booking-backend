const express = require('express');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

// --- Demo-only in-memory stores. Replace both with a real database
// (e.g. Postgres) before shipping this to real customers. ---
const users = {};       // email -> { userId, passwordHash }
const uberTokens = {};  // userId -> { accessToken, refreshToken }

const JWT_SECRET = process.env.JWT_SECRET;
const UBER_CLIENT_ID = process.env.UBER_CLIENT_ID;
const UBER_CLIENT_SECRET = process.env.UBER_CLIENT_SECRET;
const REDIRECT_URI = process.env.UBER_REDIRECT_URI; // e.g. https://yourserver.com/auth/callback

// Sandbox works immediately with no Uber approval — great for building and
// testing the whole flow. Switch UBER_ENV to "production" only once Uber has
// approved your app for the "request" scope.
const UBER_API_BASE = process.env.UBER_ENV === 'production'
  ? 'https://api.uber.com'
  : 'https://sandbox-api.uber.com';

// ---------- Your app's own accounts ----------

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (users[email]) return res.status(409).json({ error: 'Account already exists' });

  const userId = uuidv4();
  const passwordHash = await bcrypt.hash(password, 10);
  users[email] = { userId, passwordHash };

  const authToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ userId, authToken });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const authToken = jwt.sign({ userId: user.userId }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ userId: user.userId, authToken });
});

// Verifies the app's own session token on every protected request and
// attaches the real userId to req — the app never gets to just claim a userId.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing auth token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
}

// ---------- Uber connection (per customer) ----------

// The app calls this (with its own auth header) to get the URL to open in
// a browser. The userId is embedded server-side, not supplied by the client.
app.get('/uber/connect-url', requireAuth, (req, res) => {
  const authUrl = `https://auth.uber.com/oauth/v2/authorize?client_id=${UBER_CLIENT_ID}` +
    `&response_type=code&scope=request%20profile` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${req.userId}`;
  res.json({ url: authUrl });
});

// Uber redirects here once the customer approves access to their account.
app.get('/auth/callback', async (req, res) => {
  const { code, state: userId } = req.query;
  try {
    const tokenRes = await axios.post('https://auth.uber.com/oauth/v2/token', null, {
      params: {
        client_id: UBER_CLIENT_ID,
        client_secret: UBER_CLIENT_SECRET,
        grant_type: 'authorization_code',
        redirect_uri: REDIRECT_URI,
        code
      }
    });
    uberTokens[userId] = {
      accessToken: tokenRes.data.access_token,
      refreshToken: tokenRes.data.refresh_token,
      expiresAt: Date.now() + tokenRes.data.expires_in * 1000
    };
    res.redirect(`myapp://oauth/complete?userId=${userId}`);
  } catch (err) {
    res.status(500).send('Uber authorization failed');
  }
});

// Returns a valid access token for this customer, silently refreshing it
// first if it's expired or about to expire. This is what makes the Uber
// connection "one-time" from the customer's point of view.
async function getValidAccessToken(userId) {
  const entry = uberTokens[userId];
  if (!entry) return null;

  const isExpiringSoon = Date.now() > entry.expiresAt - 60000; // refresh 1 min early
  if (!isExpiringSoon) return entry.accessToken;

  try {
    const refreshRes = await axios.post('https://auth.uber.com/oauth/v2/token', null, {
      params: {
        client_id: UBER_CLIENT_ID,
        client_secret: UBER_CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: entry.refreshToken
      }
    });
    uberTokens[userId] = {
      accessToken: refreshRes.data.access_token,
      // Uber may or may not rotate the refresh token; keep the old one if not.
      refreshToken: refreshRes.data.refresh_token || entry.refreshToken,
      expiresAt: Date.now() + refreshRes.data.expires_in * 1000
    };
    return uberTokens[userId].accessToken;
  } catch (err) {
    // Refresh token itself is no longer valid — customer must reconnect.
    delete uberTokens[userId];
    return null;
  }
}

// ---------- Estimates & booking (per customer, using their own Uber token) ----------

app.get('/estimates', requireAuth, async (req, res) => {
  const { startLat, startLng, endLat, endLng } = req.query;
  const token = await getValidAccessToken(req.userId);
  if (!token) return res.status(409).json({ error: 'Customer needs to reconnect Uber' });

  try {
    const estRes = await axios.get(`${UBER_API_BASE}/v1.2/estimates/price`, {
      headers: { Authorization: `Bearer ${token}` },
      params: {
        start_latitude: startLat,
        start_longitude: startLng,
        end_latitude: endLat,
        end_longitude: endLng
      }
    });
    res.json(estRes.data.prices);
  } catch (err) {
    res.status(502).json({ error: 'Could not fetch estimates', detail: err.response?.data || err.message });
  }
});

app.post('/book', requireAuth, async (req, res) => {
  const { productId, startLat, startLng, endLat, endLng } = req.body;
  const token = await getValidAccessToken(req.userId);
  if (!token) return res.status(409).json({ error: 'Customer needs to reconnect Uber' });

  try {
    const reqRes = await axios.post(`${UBER_API_BASE}/v1.2/requests`, {
      product_id: productId,
      start_latitude: startLat,
      start_longitude: startLng,
      end_latitude: endLat,
      end_longitude: endLng
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json(reqRes.data);
  } catch (err) {
    res.status(502).json({ error: 'Booking failed', detail: err.response?.data || err.message });
  }
});

// Fail fast with a clear message instead of confusing errors later.
const required = { JWT_SECRET, UBER_CLIENT_ID, UBER_CLIENT_SECRET, REDIRECT_URI };
for (const [name, value] of Object.entries(required)) {
  if (!value) {
    console.error(`Missing required environment variable: ${name}. Set it before starting the server.`);
    process.exit(1);
  }
}

app.listen(3000, () => console.log(`Server running on port 3000 (Uber env: ${process.env.UBER_ENV || 'sandbox'})`));
