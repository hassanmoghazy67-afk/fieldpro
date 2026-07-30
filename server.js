require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const path = require('path');
const ws = require('ws');
const multer = require('multer');
// Files land in memory first (not on disk) since we immediately re-upload them
// to Supabase Storage — Railway's filesystem is ephemeral and not meant for
// persistent storage anyway. 10MB cap matches Twilio's MMS size limit, so a
// file too large for MMS gets rejected here rather than failing silently later.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ─── BUSINESS TIMEZONE (Pennsylvania / US Eastern) ─────────────────────────────
// Railway's server clock runs in UTC regardless of where Hassan or the business
// is. These helpers compute "today", date boundaries, and formatted times in
// America/New_York specifically — which automatically handles the EST/EDT
// daylight-saving switch twice a year via the IANA timezone database, no manual
// updates ever needed. This is the single source of truth for "what day/time is
// it for this business" everywhere in the backend.
const BUSINESS_TZ = 'America/New_York';

function nowInBusinessTz() {
  return new Date(new Date().toLocaleString('en-US', { timeZone: BUSINESS_TZ }));
}

// Returns today's date as 'YYYY-MM-DD' in business-local time, not UTC.
function todayInBusinessTz() {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: BUSINESS_TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date());
  const map = {}; parts.forEach(p => map[p.type] = p.value);
  return `${map.year}-${map.month}-${map.day}`;
}

// Converts any Date/timestamp to a 'YYYY-MM-DD' string in business-local time.
function dateInBusinessTz(date) {
  const d = date instanceof Date ? date : new Date(date);
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: BUSINESS_TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(d);
  const map = {}; parts.forEach(p => map[p.type] = p.value);
  return `${map.year}-${map.month}-${map.day}`;
}

// ─── LIVE PUSH (SSE) ─────────────────────────────────────────────────────────
const sseClients = new Set();
function broadcastNudge(type) {
  const payload = `event: ${type}\ndata: {}\n\n`;
  for (const client of sseClients) { try { client.write(payload); } catch(e) { sseClients.delete(client); } }
}

const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://fieldpro-production-df25.up.railway.app';

async function generateJobId() {
  // Previously called a Postgres RPC (next_job_number()) whose exact logic we
  // can't fully verify — but the evidence is damning: with exactly 5796 jobs
  // total, it was handing out "JOB-5797", identical to the total row count.
  // That's a "count of all rows + 1" calculation, not "highest existing
  // JOB-NNN number + 1" — and since 5785 of those rows are historical imports
  // using entirely different ID schemes (RWG-221, EXP7-75, YAAZ-7WHV...), that
  // count-based number collided head-on with the one real "JOB-5797" that
  // already existed, every single time, regardless of retries, since the row
  // count doesn't change between attempts. This computes the next number
  // directly and correctly from the actual jobs table in application code, so
  // it doesn't depend on a separate database function being fixed at all.
  const { data, error } = await supabase.from('jobs').select('id').ilike('id', 'JOB-%');
  if (error) throw new Error('Could not generate job ID: ' + error.message);
  let max = 0;
  for (const row of data || []) {
    const m = String(row.id).match(/^JOB-(\d+)$/);
    if (m) { const n = parseInt(m[1], 10); if (n > max) max = n; }
  }
  return `JOB-${String(max + 1).padStart(3, '0')}`;
}

const app = express();
app.set('trust proxy', 1); // Required for Railway/reverse proxy

// ─── CORS: locked to our own origins ────────────────────────────────────────────
// Previously cors() accepted ANY origin, meaning any website could make
// authenticated API calls with a stolen token from a visitor's browser.
// Now only the production app itself (and localhost during development) may
// make cross-origin requests. Same-origin requests (the normal case — the SPA
// is served from this same server) have no Origin restrictions and are unaffected.
const ALLOWED_ORIGINS = [
  'https://fieldpro-production-df25.up.railway.app',
  'http://localhost:3000',
  'http://localhost:8080'
];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false); // silently deny — no CORS headers issued
  }
}));

// ─── SECURITY HEADERS (manual, zero-dependency) ────────────────────────────────
// - X-Content-Type-Options: stops MIME-sniffing attacks on uploaded/linked files.
// - X-Frame-Options: DENY — nobody may iframe the CRM (clickjacking protection).
// - Referrer-Policy: don't leak CRM URLs (which contain job IDs) to external sites.
// - HSTS: browsers refuse plain-HTTP connections for a year after first visit.
// - CSP: pragmatic policy. The SPA uses inline scripts/handlers, so
//   'unsafe-inline' must stay for script/style — the CSP's real value here is
//   locking down connect-src (where fetch/XHR may go: only self + Google Maps),
//   frame-ancestors, object-src, and base-uri. This means even if XSS text gets
//   rendered, exfiltrating the token to an attacker's server via fetch is blocked.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), payment=()');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://maps.googleapis.com https://unpkg.com",
    "style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com",
    "font-src 'self' https://unpkg.com https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https://*.twilio.com https://maps.googleapis.com https://maps.gstatic.com https://*.googleapis.com https://*.supabase.co",
    "media-src 'self' https://*.twilio.com https://api.twilio.com",
    "connect-src 'self' https://maps.googleapis.com",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'"
  ].join('; '));
  next();
});
// Behind Railway's proxy every request arrives from the proxy IP. Without
// trust proxy, req.ip is identical for ALL users, so per-IP rate limits
// collapse into one shared pool for the whole company — one busy dispatcher
// could exhaust everyone's quota. trust proxy = 1 (exactly one hop: Railway)
// makes req.ip the real client address, so each user gets their own limit.
app.set('trust proxy', 1);

app.use(express.json());
// Twilio webhooks (SMS + voice) POST as application/x-www-form-urlencoded, NOT
// JSON. Without this parser req.body is empty for every Twilio callback — the
// exact reason inbound texts were delivered by the carrier but never appeared
// in the CRM: From/Body were undefined and the message insert silently failed.
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    // HTML must always revalidate — otherwise browsers can keep serving a stale
    // app shell for hours after a deploy (same failure mode as the old
    // cache-first service worker, just at the HTTP layer). Icons/manifest can
    // cache for a day; they rarely change.
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    else res.setHeader('Cache-Control', 'public, max-age=86400');
  }
}));

// ─── CRASH RECOVERY ─────────────────────────────────────────────────────────────
// Without these, ANY unhandled error anywhere in the app — a webhook with an
// unexpected payload, a database hiccup, a typo in a rarely-hit code path —
// takes down the entire server process, not just that one request. Railway will
// restart a crashed process automatically, but that still means real downtime
// (missed texts, dropped calls) until it comes back. These two handlers log the
// error and keep the process alive instead. They are a safety net, not a fix for
// the underlying bug — anything caught here should still get investigated.
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION — server stayed up:', err?.message, err?.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION — server stayed up:', reason?.message || reason, reason?.stack);
});

// Rate limiting
// ─── FLOOD TRACKING ───────────────────────────────────────────────────────────
// In-memory log of rate-limit hits. Resets on server restart but that's fine —
// we care about active floods, not historical ones. Capped at 1000 entries so
// it never causes a memory problem even under sustained attack.
const floodLog = [];
function recordFloodHit(ip, path) {
  floodLog.push({ ip, path, time: new Date().toISOString() });
  if (floodLog.length > 1000) floodLog.shift();
}

// ─── RATE LIMITING ────────────────────────────────────────────────────────────

// Global: 1000 requests per 15 min per IP (doubled per Hassan, July 2026).
// The CRM burns ~210 per 15 min from background polling alone, plus ~100-150
// for active usage. 1000 covers heavy multi-tab use comfortably while still blocking floods.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordFloodHit(req.ip, req.path);
    res.status(429).json({ error: 'Too many requests. Please slow down.' });
  }
});
app.use('/api/', limiter);

// Login — 20 attempts per 15 min per IP.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordFloodHit(req.ip, req.path);
    res.status(429).json({ error: 'Too many login attempts. Please wait 15 minutes and try again.' });
  }
});

// SMS opt-in (PUBLIC, no auth) — 10 per hour per IP.
const smsOptinLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordFloodHit(req.ip, req.path);
    res.status(429).json({ error: 'Too many sign-up attempts. Please try again in an hour.' });
  }
});

// SMS send (authenticated) — 160 per hour per IP.
const smsSendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 160,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordFloodHit(req.ip, req.path);
    res.status(429).json({ error: 'SMS send limit reached. Please wait before sending more messages.' });
  }
});

// AI assistant — 40 per hour per IP. Most expensive per-request cost in the stack.
const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordFloodHit(req.ip, req.path);
    res.status(429).json({ error: 'AI usage limit reached. Please wait before sending more messages.' });
  }
});

// Supabase client — ws required for Node < 22
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
  realtime: { transport: ws }
});

// Twilio client
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// ─── TWILIO WEBHOOK SIGNATURE VALIDATION ────────────────────────────────────────
// Twilio signs every webhook it sends with X-Twilio-Signature (HMAC-SHA1 over the
// full URL + sorted POST params, keyed by our auth token). Without checking it,
// ANYONE who finds these URLs can forge inbound SMS, fake tech confirmations, and
// inject bogus closing amounts straight into the finance pipeline. This middleware
// rejects any webhook POST that Twilio didn't actually send.
// Behind Railway's proxy, req.protocol/host reflect X-Forwarded-* (trust proxy is
// on), which reconstructs the exact public URL Twilio signed against.
function twilioWebhookAuth(req, res, next) {
  try {
    const signature = req.headers['x-twilio-signature'];
    if (!signature) { console.warn('Twilio webhook rejected: missing signature', req.path); return res.status(403).send('Forbidden'); }
    const url = (process.env.PUBLIC_BASE_URL || (req.protocol + '://' + req.get('host'))) + req.originalUrl;
    const valid = twilio.validateRequest(process.env.TWILIO_AUTH_TOKEN, signature, url, req.body || {});
    if (!valid) { console.warn('Twilio webhook rejected: invalid signature', req.path, 'url used:', url); return res.status(403).send('Forbidden'); }
    next();
  } catch (e) {
    console.error('twilioWebhookAuth error:', e.message);
    return res.status(403).send('Forbidden');
  }
}

// JWT middleware
// ─── AUTH: token signature + LIVE account check ─────────────────────────────────
// Previously the JWT alone was trusted for its full 7-day life: a disabled or
// deleted user kept working, and a demoted admin kept admin power, until their
// token expired. Now every request re-verifies the account against the database:
// the user must still exist, must be enabled, and role/permissions come FRESH
// from the DB — never from stale token claims. A 60-second in-memory cache keeps
// this to at most one extra DB query per user per minute (invalidated instantly
// when an admin edits/disables/deletes a user via invalidateAuthCache below).
const _authCache = new Map(); // userId -> { user, expires }
function invalidateAuthCache(userId) { if (userId) _authCache.delete(String(userId)); else _authCache.clear(); }
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  let claims;
  try { claims = jwt.verify(token, process.env.JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
  try {
    const key = String(claims.id);
    let cached = _authCache.get(key);
    if (!cached || cached.expires < Date.now()) {
      const { data: dbUser } = await supabase.from('users').select('id,name,email,role,is_enabled').eq('id', claims.id).single();
      cached = { user: dbUser || null, expires: Date.now() + 60000 };
      _authCache.set(key, cached);
    }
    if (!cached.user) return res.status(401).json({ error: 'Account no longer exists' });
    if (cached.user.is_enabled === false) return res.status(403).json({ error: 'Account disabled' });
    // id/email from token, role/name ALWAYS from the database (fresh)
    req.user = { id: claims.id, email: cached.user.email, role: cached.user.role, name: cached.user.name };
    next();
  } catch (e) {
    console.error('authMiddleware DB check failed:', e.message);
    return res.status(500).json({ error: 'Auth check failed' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// Checks a granular permission flag on the logged-in user (admins always pass).
// Usage: requirePerm('perm_view_total_revenue')
function requirePerm(flag) {
  return async (req, res, next) => {
    if (req.user.role === 'admin') return next();
    const { data: user } = await supabase.from('users').select(flag).eq('id', req.user.id).single();
    if (!user || user[flag] === false) return res.status(403).json({ error: 'Not permitted' });
    next();
  };
}

// ─── AUTH ────────────────────────────────────────────────────────────────────


// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
// EventSource can't send Authorization headers, so auth travels via query param.
// This endpoint pushes ZERO data — only a signal to refetch — so a leaked/replayed
// token here can at most tell an attacker "something changed", not any content.
// The <audio> tag can't send an Authorization header any more than EventSource
// can, so auth travels via query param, same pattern as /api/events.
// This exists because Twilio recording URLs are NOT public — they require
// HTTP Basic Auth with the Account SID/Auth Token, which is exactly why the
// browser was popping up its own native username/password prompt when the
// <audio> tag pointed straight at Twilio's raw media URL. Fetching it here,
// server-side, means the Twilio credentials never have to be shared with
// anyone using the app at all.
app.get('/api/recordings/:id/audio', async (req, res) => {
  try {
    let claims;
    try { claims = jwt.verify(req.query.token || '', process.env.JWT_SECRET); } catch { return res.status(401).end(); }
    if (!claims?.id) return res.status(401).end();
    const { data: rec } = await supabase.from('call_recordings').select('recording_url').eq('id', req.params.id).single();
    if (!rec?.recording_url) return res.status(404).end();
    const auth = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
    const twilioRes = await fetch(rec.recording_url, { headers: { Authorization: `Basic ${auth}` } });
    if (!twilioRes.ok) return res.status(502).end();
    const buf = Buffer.from(await twilioRes.arrayBuffer());
    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'private, max-age=3600');
    res.send(buf);
  } catch(e) {
    console.error('/api/recordings/:id/audio error:', e.message);
    if (!res.headersSent) res.status(500).end();
  }
});

app.get('/api/events', async (req, res) => {
  try {
    const claims = jwt.verify(req.query.token || '', process.env.JWT_SECRET);
    if (!claims?.id) return res.status(401).end();
  } catch { return res.status(401).end(); }
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.write('event: connected\ndata: {}\n\n');
  sseClients.add(res);
  const heartbeat = setInterval(() => { try { res.write(': ping\n\n'); } catch(e) {} }, 25000);
  req.on('close', () => { clearInterval(heartbeat); sseClients.delete(res); });
});

// Twilio posts here every time a sent message's status changes (queued → sent
// → delivered, or → undelivered/failed). We match it back to our row via
// MessageSid and push a live nudge so the check-mark icon updates instantly.
// Toggle a message's starred state. Starring is purely a dispatcher convenience
// (marking a message worth remembering) — no business logic depends on it.
app.put('/api/messages/:id/star', authMiddleware, async (req, res) => {
  try {
    const { data: msg, error: findErr } = await supabase.from('messages').select('starred').eq('id', req.params.id).single();
    if (findErr) { console.error('/api/messages/:id/star lookup error:', findErr.message); return res.status(500).json({ error: 'Server error' }); }
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    const { data, error } = await supabase.from('messages').update({ starred: !msg.starred }).eq('id', req.params.id).select().single();
    if (error) { console.error('/api/messages/:id/star update error:', error.message); return res.status(500).json({ error: 'Server error' }); }
    res.json(data);
  } catch(e) {
    console.error('/api/messages/:id/star error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/webhooks/sms-status', twilioWebhookAuth, async (req, res) => {
  try {
    const { MessageSid, MessageStatus } = req.body;
    if (MessageSid && MessageStatus) {
      const { data, error } = await supabase.from('messages').update({ delivery_status: MessageStatus }).eq('twilio_sid', MessageSid).select('id');
      if (error) console.error('sms-status: update failed for', MessageSid, ':', error.message);
      else if (!data || !data.length) console.warn('sms-status: no message row matched twilio_sid', MessageSid, '(status was', MessageStatus + ') — check the row exists and RLS allows this write');
      else console.log('sms-status:', MessageSid, '->', MessageStatus);
      broadcastNudge('new_message');
    }
    res.status(200).end();
  } catch(e) {
    console.error('sms-status webhook error:', e.message);
    res.status(200).end(); // Twilio just needs 200
  }
});

app.get('/api/health', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('count').single();
    if (error) {
      return res.status(503).json({ status: 'error', supabase: 'error: ' + error.message, twilio: process.env.TWILIO_ACCOUNT_SID ? 'configured' : 'missing', jwt: process.env.JWT_SECRET ? 'configured' : 'missing' });
    }
    res.json({
      status: 'ok',
      supabase: 'connected',
      twilio: process.env.TWILIO_ACCOUNT_SID ? 'configured' : 'missing',
      jwt: process.env.JWT_SECRET ? 'configured' : 'missing'
    });
  } catch(e) {
    res.status(503).json({ status: 'error', message: e.message });
  }
});

// Flood stats — admin only. Returns recent rate-limit hits so the Settings
// system status panel can show if the CRM is under attack.
app.get('/api/admin/flood-stats', authMiddleware, adminOnly, (req, res) => {
  const now = Date.now();
  const last1h = floodLog.filter(h => now - new Date(h.time).getTime() < 60 * 60 * 1000);
  const last15m = floodLog.filter(h => now - new Date(h.time).getTime() < 15 * 60 * 1000);
  // Count hits per IP
  const ipCounts = {};
  last1h.forEach(h => { ipCounts[h.ip] = (ipCounts[h.ip] || 0) + 1; });
  const topOffenders = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, count]) => ({ ip, count }));
  res.json({
    total_hits_last_1h: last1h.length,
    total_hits_last_15m: last15m.length,
    top_offenders: topOffenders,
    recent: floodLog.slice(-20).reverse() // last 20 hits, newest first
  });
});


// ─── SUPABASE PAGINATION HELPER ───────────────────────────────────────────────
// Supabase silently caps every select at 1000 rows. With 1500+ historical jobs
// imported, any "fetch all" query truncates data and corrupts trends/finance.
// This helper pages through in 1000-row chunks until exhausted.
// Usage: const rows = await fetchAllRows(() => supabase.from('jobs').select('*').order('created_at', { ascending: false }));
// ─── CLOSING-FIRST REVENUE ──────────────────────────────────────────────────────
// The job CLOSING (closing_total / closing_parts / closing_commission_*) is the
// system of record for what a job earned. Invoices are customer-facing
// presentation only — editing an invoice's breakdown never changes reported
// revenue. Legacy jobs closed before this system exist only as paid invoices,
// so aggregations fall back to the paid invoice for jobs WITHOUT a closing.
function jobRevenueResolver(jobs, invoices) {
  const closingByJob = new Map();
  (jobs || []).forEach(j => { if (j.closing_total !== null && j.closing_total !== undefined) closingByJob.set(j.id, parseFloat(j.closing_total) || 0); });
  const paidInvByJob = new Map();
  (invoices || []).forEach(i => { if (i.job_id && i.status === 'paid') paidInvByJob.set(i.job_id, (paidInvByJob.get(i.job_id) || 0) + (parseFloat(i.total) || 0)); });
  return {
    forJob: (jobId) => closingByJob.has(jobId) ? closingByJob.get(jobId) : (paidInvByJob.get(jobId) || 0),
    hasClosing: (jobId) => closingByJob.has(jobId)
  };
}

async function fetchAllRows(buildQuery) {
  const PAGE = 1000;
  let all = [], from = 0;
  while (true) {
    const { data, error } = await buildQuery().range(from, from + PAGE - 1);
    if (error) throw new Error(error.message);
    all = all.concat(data || []);
    if (!data || data.length < PAGE) break;
    from += PAGE;
  }
  return all;
}

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    // One generic message for every failure mode. The old distinct messages
    // ("No account found with that email" vs "Incorrect password") let anyone
    // enumerate which emails have CRM accounts; raw Supabase errors leaked
    // internal details. Disabled accounts still get their specific message —
    // that's information the legitimate owner needs.
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error && error.code !== 'PGRST116') { console.error('Login DB error:', error.message); return res.status(500).json({ error: 'Login failed. Please try again.' }); }
    if (!user || !user.password_hash) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.is_enabled === false) return res.status(403).json({ error: 'This account has been disabled. Contact your administrator.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' });
    await supabase.from('users').update({ status: 'online' }).eq('id', user.id);
    const PERM_FIELDS = ['perm_view_jobs','perm_edit_jobs','perm_delete_jobs','perm_view_customers','perm_view_sms','perm_view_booking','perm_view_finance_tools','perm_view_total_revenue','perm_view_reports','perm_view_workflows','perm_view_ai_assistant','perm_view_closing_messages','perm_manage_techs','perm_view_settings'];
    const perms = {}; PERM_FIELDS.forEach(f => perms[f] = user[f] !== false);
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, color: user.color, initials: user.initials, ...perms } });
  } catch(e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Login failed: ' + e.message });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    await supabase.from('users').update({ status: 'offline' }).eq('id', req.user.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Current password incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from('users').update({ password_hash: hash }).eq('id', req.user.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get('/api/users', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('users').select('id,name,email,role,phone,color,initials,status,is_enabled,legacy_external_id,can_view_all_jobs,can_edit_jobs,can_view_finance,use_masking,direct_phone,default_commission_type,default_commission_value,commission_rules,qualified_job_types,area_restriction_enabled,coverage_zips,coverage_areas,perm_view_jobs,perm_edit_jobs,perm_delete_jobs,perm_view_customers,perm_view_sms,perm_view_booking,perm_view_finance_tools,perm_view_total_revenue,perm_view_reports,perm_view_workflows,perm_view_ai_assistant,perm_view_closing_messages,perm_manage_techs,perm_view_settings,created_at').order('created_at');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/users/:id/permissions', authMiddleware, adminOnly, async (req, res) => {
  invalidateAuthCache(req.params.id);
  try {
  const PERM_FIELDS = ['perm_view_jobs','perm_edit_jobs','perm_delete_jobs','perm_view_customers','perm_view_sms','perm_view_booking','perm_view_finance_tools','perm_view_total_revenue','perm_view_reports','perm_view_workflows','perm_view_ai_assistant','perm_view_closing_messages','perm_manage_techs','perm_view_settings'];
    const update = {};
    PERM_FIELDS.forEach(f => { if (req.body[f] !== undefined) update[f] = !!req.body[f]; });
    const { data, error } = await supabase.from('users').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users/:id/permissions error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { name, email, password, role, phone, color, default_commission_type, default_commission_value, commission_rules, use_masking, sms_only, legacy_external_id, qualified_job_types } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    // SMS-only techs have no CRM login at all — admin and any tech meant to log in
    // still need a real email + password. This is enforced here in code, not the
    // database, so existing accounts are completely unaffected.
    if (!sms_only && (!email || !password)) return res.status(400).json({ error: 'Email and password required (or mark as SMS-only with no login)' });
    if (sms_only && !phone) return res.status(400).json({ error: 'Phone required for SMS-only techs — that\'s their only way to receive jobs' });
    const hash = password ? await bcrypt.hash(password, 10) : null;
    const initials = name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
    const { data, error } = await supabase.from('users').insert({
      name, email: email || null, password_hash: hash, role: role || 'tech', phone, color: color || '#1e6fff', initials,
      default_commission_type: default_commission_type || 'percentage',
      default_commission_value: default_commission_value != null ? parseFloat(default_commission_value) : 30,
      commission_rules: commission_rules || [],
      qualified_job_types: qualified_job_types || [],
      use_masking: use_masking !== undefined ? use_masking : true,
      legacy_external_id: legacy_external_id || null,
      is_enabled: true
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Bulk-import SMS-only techs in one request — used for one-time migrations from
// another dispatch system. Skips any tech whose legacy_external_id already
// exists, so it's safe to re-run without creating duplicates.
app.post('/api/users/bulk-import', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { techs } = req.body;
    if (!Array.isArray(techs) || !techs.length) return res.status(400).json({ error: 'techs array required' });
    const created = [];
    const skipped = [];
    for (const t of techs) {
      if (!t.name || !t.phone) { skipped.push({ ...t, reason: 'missing name or phone' }); continue; }
      if (t.legacy_external_id) {
        const { data: existing } = await supabase.from('users').select('id').eq('legacy_external_id', t.legacy_external_id).single();
        if (existing) { skipped.push({ ...t, reason: 'already imported' }); continue; }
      }
      const initials = t.name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
      const { data, error } = await supabase.from('users').insert({
        name: t.name, phone: t.phone, role: 'tech', color: '#1e6fff', initials,
        legacy_external_id: t.legacy_external_id || null, is_enabled: true, use_masking: true,
        default_commission_type: 'percentage', default_commission_value: 30, commission_rules: [], qualified_job_types: []
      }).select().single();
      if (error) skipped.push({ ...t, reason: error.message });
      else created.push(data);
    }
    res.json({ created: created.length, skipped: skipped.length, created_techs: created, skipped_details: skipped });
  } catch(e) {
    console.error('/api/users/bulk-import error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  invalidateAuthCache(req.params.id);
  try {
  const { name, role, phone, color, status, can_view_all_jobs, can_edit_jobs, can_view_finance, default_commission_type, default_commission_value, commission_rules, use_masking, qualified_job_types, is_enabled, area_restriction_enabled, coverage_zips, coverage_areas } = req.body;
    const initials = name ? name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase() : undefined;
    const update = { name, role, phone, color, status, can_view_all_jobs, can_edit_jobs, can_view_finance, default_commission_type, use_masking };
    if (default_commission_value !== undefined) update.default_commission_value = parseFloat(default_commission_value);
    if (commission_rules !== undefined) update.commission_rules = commission_rules;
    if (qualified_job_types !== undefined) update.qualified_job_types = qualified_job_types;
    if (is_enabled !== undefined) update.is_enabled = is_enabled;
    if (area_restriction_enabled !== undefined) update.area_restriction_enabled = area_restriction_enabled;
    if (coverage_zips !== undefined) update.coverage_zips = coverage_zips;
    if (coverage_areas !== undefined) update.coverage_areas = coverage_areas;
    if (initials) update.initials = initials;
    Object.keys(update).forEach(k => update[k] === undefined && delete update[k]);
    const { data, error } = await supabase.from('users').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Admin resets any user's password (e.g. dispatcher forgot theirs, or initial
// credential handout). User can then change it themselves in Settings → Password.
app.put('/api/users/:id/reset-password', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { new_password } = req.body;
    if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const password_hash = await bcrypt.hash(new_password, 10);
    const { error } = await supabase.from('users').update({ password_hash }).eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('user', req.params.id, req.user.id, req.user.name, 'password_reset', 'Admin reset user password');
    res.json({ success: true });
  } catch(e) {
    console.error('/api/users/:id/reset-password error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  invalidateAuthCache(req.params.id);
  try {
  const { error } = await supabase.from('users').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/users/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── CUSTOMERS ───────────────────────────────────────────────────────────────

app.get('/api/customers', authMiddleware, requirePerm('perm_view_customers'), async (req, res) => {
  try {
  const data = await fetchAllRows(() => supabase.from('customers').select('*').order('name'));
    res.json(data);
  } catch(e) {
    console.error('/api/customers error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/customers', authMiddleware, async (req, res) => {
  try {
  const { name, phone, email, address, notes } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });
    const { data, error } = await supabase.from('customers').insert({ name, phone, email, address, notes }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await createNotification('new_customer', 'New Customer Added', `${name} was added to customers`);
    res.json(data);
  } catch(e) {
    console.error('/api/customers error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/customers/:id', authMiddleware, async (req, res) => {
  try {
  const { name, phone, email, address, notes } = req.body;
    const { data, error } = await supabase.from('customers').update({ name, phone, email, address, notes }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/customers/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/customers/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { count: jobCount } = await supabase.from('jobs').select('id', { count: 'exact', head: true }).eq('customer_id', req.params.id);
    if (jobCount && jobCount > 0) {
      return res.status(409).json({ error: `Cannot delete — this customer has ${jobCount} job(s) on record. Remove or reassign those jobs first.`, job_count: jobCount });
    }
    const { error } = await supabase.from('customers').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/customers/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── JOBS ─────────────────────────────────────────────────────────────────────

// Single-job fetch — the frontend's fallback when a job isn't in its in-memory
// cache (created/changed after that tab booted). Tech accounts stay scoped to
// their own jobs, same as the list endpoint.
app.get('/api/jobs/one/:id', authMiddleware, async (req, res) => {
  try {
    let q = supabase.from('jobs').select('*').eq('id', req.params.id);
    if (req.user.role === 'tech') q = q.eq('tech_id', req.user.id);
    const { data, error } = await q.single();
    if (error || !data) return res.status(404).json({ error: 'Job not found' });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/one/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/jobs', authMiddleware, async (req, res) => {
  try {
  const data = await fetchAllRows(() => {
      let q = supabase.from('jobs').select('*').order('created_at', { ascending: false });
      // Techs are ALWAYS scoped to their own jobs. (The old `!req.query.all` escape
      // hatch let any tech see every job in the company by adding ?all=1 — removed.)
      if (req.user.role === 'tech') q = q.eq('tech_id', req.user.id);
      return q;
    });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/jobs', authMiddleware, async (req, res) => {
  try {
    const { title, customer_id, customer_name, phone, address, city, state, job_type, car_make_model, car_year, tech_id, tech_name, priority, status, notes, job_date, scheduled_date, zip_code, source } = req.body;
    // Customer identity = PHONE NUMBER, never name (half the customers are
    // "Mr"/"Mrs"). Link to the existing customer with this phone, else create.
    let resolvedCustomerId = customer_id || null;
    if (phone) {
      const norm = String(phone).replace(/\D/g, '').slice(-10);
      if (norm.length === 10) {
        const { data: existingC } = await supabase.from('customers').select('id,phone');
        const hit = (existingC || []).find(c => String(c.phone || '').replace(/\D/g, '').slice(-10) === norm);
        if (hit) resolvedCustomerId = hit.id;
        else {
          const { data: newC } = await supabase.from('customers').insert({ name: customer_name || 'Customer', phone }).select().single();
          if (newC) resolvedCustomerId = newC.id;
        }
      }
    }
    if (!title) return res.status(400).json({ error: 'Title required' });
    // generateJobId() calls next_job_number(), which now derives the next
    // number fresh from the actual jobs table every time (migration fix) —
    // but as a second line of defense against the exact "duplicate key value
    // violates unique constraint jobs_pkey" error, retry a few times on a
    // genuine collision (e.g. two dispatchers creating a job in the same
    // instant) instead of surfacing a raw database error to the user.
    let data, error, id;
    for (let attempt = 0; attempt < 5; attempt++) {
      id = await generateJobId();
      ({ data, error } = await supabase.from('jobs').insert({
        id, title, customer_id: resolvedCustomerId, customer_name, phone, address, job_type, car_make_model, car_year,
        tech_id, tech_name, priority: priority || 'med', status: status || 'new', notes, job_date, scheduled_date,
        city: city || null, state: state || null, zip_code: zip_code || null, source: source || null,
        created_by_user_id: req.user.id, created_by_name: req.user.name
      }).select().single());
      if (!error || error.code !== '23505') break; // only retry on a real unique-key collision
      console.warn('Job ID collision on', id, '— retrying (attempt', attempt + 1, ')');
    }
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('job', id, req.user.id, req.user.name, 'created', `Created job for ${customer_name || 'unknown customer'}`);
    broadcastNudge('jobs_changed');
    await createNotification('new_job', 'New Job Created', `${id} — ${title}`);
    runEventWorkflows('new_job', data).catch(() => {});
    // Assignment no longer auto-texts the tech. Dispatch reviews the job and
    // clicks "Send to Tech" (POST /api/jobs/:id/send-to-tech), which delivers
    // the ticket as an SMS and drops a ticket card into the chat thread.
    if (tech_id && tech_name) {
      await createNotification('job_assigned', 'Job Assigned', `${id} assigned to ${tech_name}`);
      await allocateExtension(id).catch(() => {});
      sendJobAssignmentAudit(data, null).catch(() => {});
      runEventWorkflows('job_assigned', data).catch(() => {});
    }
    broadcastNudge('job_change');
    res.json(data);
  } catch(e) {
    console.error('/api/jobs POST error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/jobs/:id', authMiddleware, requirePerm('perm_edit_jobs'), async (req, res) => {
  try {
    const { data: old } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    const update = { ...req.body, updated_at: new Date().toISOString() };
    // Mark assignment timestamp + reset confirmation when tech changes. Job-type and
    // area qualification are enforced by only listing the right techs in the dropdown
    // (see /api/jobs/:id/assignable-techs) — not by rejecting the assignment here.
    // This is intentional: the picker should just show the right options, not error.
    if (update.tech_id && update.tech_id !== old?.tech_id) {
      update.assigned_at = new Date().toISOString();
      update.confirmed_by_tech = false;
      update.confirmed_at = null;
    }
    const { data, error } = await supabase.from('jobs').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (update.status && update.status !== old?.status) {
      await logHistory(req.params.id, req.user.id, req.user.name, 'Status changed', 'status', old?.status, update.status);
      // Status-specific handling. The old code fired a "Job Completed" notification
      // and the completion workflows on EVERY status change — cancelling a job
      // announced it as done and could text the customer a receipt/thank-you.
      // Now: done → completion notification + 'job_done' + 'status_change'
      // workflows; cancelled → cancellation notification + 'job_cancelled'
      // workflows ONLY (never the generic completion-era ones); anything else →
      // a plain status notification + 'status_change' workflows.
      if (update.status === 'done') {
        await createNotification('job_done', 'Job Completed', req.params.id + ' marked as done');
        runEventWorkflows('job_done', data).catch(() => {});
        runEventWorkflows('status_change', data).catch(() => {});
      } else if (update.status === 'cancelled') {
        await createNotification('job_cancelled', 'Job Cancelled', req.params.id + ' was cancelled');
        runEventWorkflows('job_cancelled', data).catch(() => {});
      } else {
        await createNotification('status_change', 'Job Status Updated', `${req.params.id}: ${old?.status || '—'} → ${update.status}`);
        runEventWorkflows('status_change', data).catch(() => {});
      }
    }
    if (update.tech_name && update.tech_name !== old?.tech_name) {
      await logHistory(req.params.id, req.user.id, req.user.name, 'Tech assigned', 'tech_name', old?.tech_name, update.tech_name);
      // No auto-SMS on assignment anymore: dispatch reviews, then clicks
      // "Send to Tech" which fires POST /api/jobs/:id/send-to-tech. That
      // endpoint texts the ticket AND stores it as a ticket card in the chat.
      await allocateExtension(req.params.id).catch(() => {});
      sendJobAssignmentAudit(data, old?.tech_name).catch(() => {});
      runEventWorkflows('job_assigned', data).catch(() => {});
    }
    broadcastNudge('job_change');
    broadcastNudge('jobs_changed');
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id PUT error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Extracts a US 5-digit zip code from a free-text address. Falls back to the
// job's manually-set zip_code column if parsing fails.
// Appends the required opt-out disclosure to a customer-facing SMS, but only
// the first time we've ever texted that specific number — carriers expect this
// disclosure on initial contact, not repeated on every message. The wording
// invites a reply without actually gating future messages on getting one —
// the system keeps sending normally either way; this is just the framing
// shown to the customer on their first text from us.
async function appendComplianceFooterIfFirstContact(phone, body) {
  try {
    const { data: priorMessages } = await supabase.from('messages').select('id').eq('contact_phone', phone).eq('direction', 'out').limit(1);
    if (priorMessages && priorMessages.length > 0) return body; // not their first text from us — keep it short
    return `${body}\n\nMsg & data rates may apply. Reply SUBSCRIBE to confirm or STOP to unsubscribe.`;
  } catch(e) {
    return `${body}\n\nMsg & data rates may apply. Reply SUBSCRIBE to confirm or STOP to unsubscribe.`;
  }
}

function extractZip(address, fallback) {
  if (!address) return fallback || null;
  const match = address.match(/\b(\d{5})(?:-\d{4})?\b/);
  return match ? match[1] : (fallback || null);
}

// Single source of truth for "can this tech be assigned to this job" — combines
// job-type qualification (Phase: tech qualifications) and area coverage (zips or
// region names). Both checks are opt-in per tech: if a tech has no restrictions
// configured, they're assignable to everything, so nobody is silently locked out
// until an admin actually sets up qualifications/coverage for them.
function isTechAssignableToJob(tech, job) {
  const qualifiedTypes = tech.qualified_job_types || [];
  if (qualifiedTypes.length > 0 && job.job_type && !qualifiedTypes.includes(job.job_type)) return false;

  if (tech.area_restriction_enabled) {
    const zips = tech.coverage_zips || [];
    const areas = (tech.coverage_areas || []).map(a => a.toLowerCase());
    if (zips.length === 0 && areas.length === 0) return false; // restriction on but nothing configured = covers nowhere
    const jobZip = extractZip(job.address, job.zip_code);
    const zipMatch = jobZip && zips.includes(jobZip);
    const addressLower = (job.address || '').toLowerCase();
    const areaMatch = areas.some(a => addressLower.includes(a));
    if (!zipMatch && !areaMatch) return false;
  }
  return true;
}

// Returns only the techs who are actually assignable to a given job — combining
// job-type qualification and area coverage — so the frontend dropdown only ever
// shows the right options instead of erroring after a bad pick.
app.get('/api/jobs/:id/assignable-techs', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('job_type,address,zip_code').eq('id', req.params.id).single();
    const { data: techs } = await supabase.from('users').select('*').eq('role', 'tech').eq('is_enabled', true);
    const assignable = (techs || []).filter(t => !job || isTechAssignableToJob(t, job));
    res.json(assignable.map(t => ({ id: t.id, name: t.name, color: t.color, initials: t.initials })));
  } catch(e) {
    console.error('/api/jobs/:id/assignable-techs error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Same logic, but for the New Job form before a job exists yet — takes job_type
// and address as query params instead of looking up an existing job.
app.get('/api/techs/assignable', authMiddleware, async (req, res) => {
  try {
  const { job_type, address, zip_code } = req.query;
    const { data: techs } = await supabase.from('users').select('*').eq('role', 'tech').eq('is_enabled', true);
    const fakeJob = { job_type, address, zip_code };
    const assignable = (techs || []).filter(t => isTechAssignableToJob(t, fakeJob));
    res.json(assignable.map(t => ({ id: t.id, name: t.name, color: t.color, initials: t.initials })));
  } catch(e) {
    console.error('/api/techs/assignable error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

async function sendJobAssignmentAudit(job, previousTechName) {
  const { data: setting } = await supabase.from('settings').select('value').eq('key', 'admin_report_job_assignments').single();
  if (setting?.value === 'false') return;
  const zip = extractZip(job.address, job.zip_code);
  const isReassignment = previousTechName && previousTechName !== job.tech_name;
  const newCount = (job.assignment_audit_count || 0) + 1;
  await supabase.from('jobs').update({ assignment_audit_count: newCount }).eq('id', job.id);
  const lines = [
    isReassignment ? `🔁 Job REASSIGNED — ${job.id}` : `📋 Job assigned — ${job.id}`,
    `Type: ${job.job_type || job.title || '—'}`,
    `Zip: ${zip || '—'}`,
    `Tech: ${job.tech_name || '—'}`
  ];
  if (isReassignment) lines.push(`(was: ${previousTechName})`);
  await sendAdminReport('job_assignment', lines.join('\n'));
}

// ─── EXTENSION / IVR CALLING SYSTEM ─────────────────────────────────────────────
// Each job gets a 3-digit extension ('000'-'999'). A tech calls the fixed business
// number, the IVR asks for the extension, and the system connects them to the
// customer's real number — which the tech never sees directly. Extensions free up
// automatically after inactivity or once the job closes, and get recycled.

// Expires any extension that's been inactive too long, or attached to a closed job,
// freeing the 3-digit code for reuse. Called before allocating a new one and also
// periodically from the alert engine loop.
async function expireStaleExtensions() {
  const settings = await getSettingsMap();
  const inactivityHours = parseFloat(settings.extension_inactivity_hours || '48');
  const cutoff = new Date(Date.now() - inactivityHours * 3600000).toISOString();
  // Free extensions on jobs that are done/cancelled
  await supabase.from('jobs').update({ extension_active: false, call_extension: null })
    .eq('extension_active', true).in('status', ['done', 'cancelled']);
  // Free extensions that haven't been used (or created) recently
  const { data: stale } = await supabase.from('jobs').select('id,extension_created_at,extension_last_used_at')
    .eq('extension_active', true);
  for (const job of stale || []) {
    const lastTouch = job.extension_last_used_at || job.extension_created_at;
    if (lastTouch && new Date(lastTouch) < new Date(cutoff)) {
      await supabase.from('jobs').update({ extension_active: false, call_extension: null }).eq('id', job.id);
    }
  }
}

// Allocates a free 3-digit extension for a job. Reuses any code not currently
// active on another job. Returns the extension string, or null if the pool
// (000-999, minus reserved 000/911-style codes) is somehow exhausted.
async function allocateExtension(jobId, forceNew) {
  await expireStaleExtensions();
  if (!forceNew) {
    const { data: existing } = await supabase.from('jobs').select('call_extension').eq('id', jobId).single();
    if (existing?.call_extension) return existing.call_extension; // already has one, reuse it
  }

  const { data: active } = await supabase.from('jobs').select('call_extension').eq('extension_active', true);
  const taken = new Set((active || []).map(j => j.call_extension));
  // RANDOM 3-digit codes, not sequential — shuffle the candidate pool so
  // extensions don't hand out predictably as 001, 002, 003...
  const candidates = [];
  for (let i = 0; i <= 999; i++) candidates.push(String(i).padStart(3, '0'));
  for (let i = candidates.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
  }
  for (const code of candidates) {
    if (taken.has(code)) continue;
    // Re-check right before claiming — two simultaneous assignments used to be
    // able to pick the same code, which then crashed the old .single() lookup
    // for BOTH jobs' callers.
    const { data: clash } = await supabase.from('jobs').select('id').eq('call_extension', code).eq('extension_active', true).limit(1);
    if (clash && clash.length) { taken.add(code); continue; }
    await supabase.from('jobs').update({
      call_extension: code, extension_active: true,
      extension_created_at: new Date().toISOString(), extension_last_used_at: new Date().toISOString()
    }).eq('id', jobId);
    return code;
  }
  return null; // pool exhausted — extremely unlikely at this business's scale
}

// ─── CLOSING TICKET SAFETY CHECK ──────────────────────────────────────────────
// Called by the frontend right before a job is closed, to warn if the tech
// closing it isn't the last tech who was actually active in the job's chat thread.
app.get('/api/jobs/:id/close-check', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (!job.last_tech_message_by || !job.tech_name || job.last_tech_message_by === job.tech_name) {
      return res.json({ mismatch: false });
    }
    res.json({
      mismatch: true,
      assigned_tech: job.tech_name,
      last_active_tech: job.last_tech_message_by,
      last_message_at: job.last_tech_message_at
    });
  } catch(e) {
    console.error('/api/jobs/:id/close-check error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/jobs/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const jobId = req.params.id;
    // Several tables reference job_id as a foreign key — clean those up first so
    // the delete doesn't get blocked by a constraint violation. Admin deletion is
    // meant to be unrestricted, so this just clears the path rather than asking
    // the admin to do it manually.
    await supabase.from('ticket_history').delete().eq('job_id', jobId);
    await supabase.from('call_recordings').delete().eq('job_id', jobId);
    await supabase.from('extension_call_log').delete().eq('job_id', jobId);
    await supabase.from('alerts').delete().eq('job_id', jobId);
    await supabase.from('messages').update({ job_id: null }).eq('job_id', jobId); // keep the message, just unlink it
    await supabase.from('bookings').update({ job_id: null }).eq('job_id', jobId); // keep the booking record, unlink it
    await supabase.from('invoices').delete().eq('job_id', jobId);
    const { error } = await supabase.from('jobs').delete().eq('id', jobId);
    if (error) return res.status(500).json({ error: error.message });
    broadcastNudge('job_change');
    broadcastNudge('jobs_changed');
    res.json({ success: true });
  } catch(e) {
    console.error('/api/jobs/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── INVOICES ─────────────────────────────────────────────────────────────────

app.get('/api/invoices', authMiddleware, async (req, res) => {
  try {
  const data = await fetchAllRows(() => supabase.from('invoices').select('*').order('created_at', { ascending: false }));
  const error = null;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/invoices error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invoices', authMiddleware, async (req, res) => {
  try {
  const { job_id, customer_id, customer_name, tech_id, tech_name, line_items, tax_rate } = req.body;
    const count = await supabase.from('invoices').select('id', { count: 'exact', head: true });
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'invoice_prefix').single();
    const prefix = settings?.value || 'INV';
    const num = String((count.count || 0) + 1).padStart(3, '0');
    const id = `${prefix}-${num}`;
    const subtotal = line_items.reduce((a, i) => a + (i.qty * i.rate), 0);
    const tr = tax_rate || 8.5;
    const tax_amount = subtotal * (tr / 100);
    const total = subtotal + tax_amount;
    const { data, error } = await supabase.from('invoices').insert({ id, job_id, customer_id, customer_name, tech_id, tech_name, line_items, subtotal, tax_rate: tr, tax_amount, total, status: 'unpaid' }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (job_id) await supabase.from('jobs').update({ invoice_id: id, status: 'done' }).eq('id', job_id);
    res.json(data);
  } catch(e) {
    console.error('/api/invoices error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/invoices/:id/pay', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('invoices').update({ status: 'paid', paid_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await createNotification('payment', 'Payment Received', `Invoice ${req.params.id} marked as paid — $${data.total}`);
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/:id/pay error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invoices/:id/send', authMiddleware, smsSendLimiter, async (req, res) => {
  try {
    const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    const { data: customer } = await supabase.from('customers').select('phone,email').eq('id', inv.customer_id).single();
    const { data: bizSettings } = await supabase.from('settings').select('key,value');
    const settings = {};
    bizSettings?.forEach(s => settings[s.key] = s.value);
    const msg = `${settings.business_name || 'FieldPro'} Invoice ${inv.id}\nAmount: $${inv.total?.toFixed(2)}\nStatus: ${inv.status}\n${settings.invoice_footer || 'Thank you for your business!'}`;
    if (customer?.phone) {
      const finalMsg = await appendComplianceFooterIfFirstContact(customer.phone, msg);
      await twilioClient.messages.create({ body: finalMsg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
      await supabase.from('invoices').update({ sent_to_customer: true }).eq('id', req.params.id);
      res.json({ success: true, method: 'sms' });
    } else { res.status(400).json({ error: 'No customer phone on file' }); }
  } catch (e) {
    console.error('/api/invoices/:id/send error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── MESSAGES / SMS ───────────────────────────────────────────────────────────

// Finds the most relevant open job for a phone number, checking both as a
// customer's number and a tech's number — used to auto-link outbound messages
// to a ticket, mirroring the same attribution the inbound webhook already does
// for tech replies. Without this, an outbound message would have no job_id at
// all, making "click the ticket ID from this message" impossible.
async function findRelevantJobForPhone(phone) {
  if (!phone) return null;
  const { data: asCustomerJobs } = await supabase.from('jobs').select('id,assigned_at').eq('phone', phone).in('status', ['new','assigned','in-progress']).order('assigned_at', { ascending: false }).limit(1);
  if (asCustomerJobs?.[0]) return asCustomerJobs[0].id;
  const { data: tech } = await supabase.from('users').select('id').eq('phone', phone).single();
  if (tech) {
    const { data: asTechJobs } = await supabase.from('jobs').select('id,assigned_at').eq('tech_id', tech.id).in('status', ['assigned','in-progress']).order('assigned_at', { ascending: false }).limit(1);
    if (asTechJobs?.[0]) return asTechJobs[0].id;
  }
  return null;
}

app.get('/api/messages', authMiddleware, requirePerm('perm_view_sms'), async (req, res) => {
  try {
  const data = await fetchAllRows(() => supabase.from('messages').select('*').order('created_at', { ascending: false }));
    res.json(data);
  } catch(e) {
    console.error('/api/messages error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/messages/:contact', authMiddleware, async (req, res) => {
  try {
  const contactParam = decodeURIComponent(req.params.contact);
  // Conversations are genuinely identified by phone number, not by name — the
  // same number's stored contact_name can change over time (e.g. before vs
  // after being saved as a customer), so filtering by name alone could split
  // one real conversation across multiple inconsistent buckets. The :contact
  // param may be a phone number (preferred) or, for backward compatibility, a
  // name — we match on phone if it looks like one, otherwise fall back to name.
  const looksLikePhone = /^\+?[\d\s\-\(\)]{7,}$/.test(contactParam);
  const data = await fetchAllRows(() => {
    let q = supabase.from('messages').select('*').order('created_at');
    return looksLikePhone ? q.eq('contact_phone', contactParam) : q.eq('contact_name', contactParam);
  });
  let readQuery = supabase.from('messages').update({ read: true }).eq('direction', 'in');
  readQuery = looksLikePhone ? readQuery.eq('contact_phone', contactParam) : readQuery.eq('contact_name', contactParam);
  await readQuery;
    res.json(data);
  } catch(e) {
    console.error('/api/messages/:contact error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── SEND JOB TICKET TO TECH ──────────────────────────────────────────────────
// Dispatch clicks "Send to Tech": texts the full ticket to the tech's phone AND
// stores it as a kind='job_ticket' message, so it renders as a ticket card in
// the chat thread with its own quick-actions menu. Used for first send and
// resends (reassignments just call it again for the new tech).
app.post('/api/jobs/:id/send-to-tech', authMiddleware, smsSendLimiter, async (req, res) => {
  try {
    const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (!job.tech_id) return res.status(400).json({ error: 'Assign a tech first' });
    const { data: tech } = await supabase.from('users').select('id,name,phone,use_masking').eq('id', job.tech_id).single();
    if (!tech?.phone) return res.status(400).json({ error: `${job.tech_name || 'Tech'} has no phone number on file` });

    // ── CALL MASKING ── For techs with masking on (the default), the ticket must
    // NEVER contain the customer's direct number. Instead it carries the host
    // (business Twilio) number plus the job's 3-digit extension — the tech dials
    // the host number, punches the ext, and the system bridges to the customer
    // showing only the business caller ID. An extension is allocated here if the
    // job doesn't have an active one yet.
    let phoneLine = job.phone || null;
    if (tech.use_masking !== false) {
      let ext = (job.extension_active && job.call_extension) ? job.call_extension : null;
      if (!ext) ext = await allocateExtension(job.id).catch(() => null);
      const dialInNumber = process.env.TWILIO_VOICE_NUMBER || process.env.TWILIO_PHONE_NUMBER;
      phoneLine = ext
        ? `Call ${dialInNumber} ext ${ext}`
        : null; // no ext available: send NO number at all rather than leaking the direct one
      if (!ext) console.error('send-to-tech: masking on but no extension available for', job.id);
    }

    // Clean label-free ticket format per Hassan's spec: id, source, type,
    // customer, phone on its OWN row, address — one item per line, no labels.
    const parts = [
      job.id,
      job.source || null,
      job.title || job.job_type || 'Service',
      job.customer_name || null,
      phoneLine,
      job.address || null,
      (job.car_year || job.car_make_model) ? [job.car_year, job.car_make_model].filter(Boolean).join(' ') : null,
      job.scheduled_date ? new Date(job.scheduled_date).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZone: 'America/New_York' }) : null,
      job.notes || null
    ].filter(Boolean);
    const body = parts.join('\n');
    const msg = await twilioClient.messages.create({ body, from: process.env.TWILIO_PHONE_NUMBER, to: tech.phone, statusCallback: `${PUBLIC_BASE_URL}/api/webhooks/sms-status` });
    await supabase.from('jobs').update({ tech_sms_status: 'sent', tech_sms_error: null, tech_sms_attempted_at: new Date().toISOString() }).eq('id', job.id);
    const { data: stored } = await supabase.from('messages').insert({
      contact_name: tech.name, contact_phone: tech.phone, contact_type: 'tech',
      direction: 'out', body, twilio_sid: msg.sid, read: true, job_id: job.id, kind: 'job_ticket',
      sent_by_user_id: req.user.id, sent_by_name: req.user.name
    }).select().single();
    await logAudit('job', job.id, req.user.id, req.user.name, 'ticket_sent', `Ticket sent to ${tech.name}`);
    res.json({ success: true, message: stored });
  } catch(e) {
    console.error('/api/jobs/:id/send-to-tech error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Marks a conversation's inbound messages as read (frontend calls this when a
// chat is opened — was previously called but never implemented).
// ─── THREAD MANAGEMENT (admin) ────────────────────────────────────────────────
// Archive hides a conversation from the active list (reversible); delete
// permanently removes every message exchanged with that phone number.
app.put('/api/messages/thread/archive', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { phone, archived } = req.body;
    if (!phone) return res.status(400).json({ error: 'phone required' });
    const { error } = await supabase.from('messages').update({ archived: archived !== false }).eq('contact_phone', phone);
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('message', phone, req.user.id, req.user.name, archived !== false ? 'thread_archived' : 'thread_unarchived', `Thread ${phone}`);
    res.json({ success: true });
  } catch(e) { if (!res.headersSent) res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/messages/thread', authMiddleware, adminOnly, async (req, res) => {
  try {
    const phone = req.query.phone;
    if (!phone) return res.status(400).json({ error: 'phone required' });
    const { error } = await supabase.from('messages').delete().eq('contact_phone', phone);
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('message', phone, req.user.id, req.user.name, 'thread_deleted', `Deleted all messages with ${phone}`);
    res.json({ success: true });
  } catch(e) { if (!res.headersSent) res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/messages/mark-read', authMiddleware, async (req, res) => {
  try {
    const { contact_name, contact_phone } = req.body;
    let q = supabase.from('messages').update({ read: true }).eq('direction', 'in');
    if (contact_phone) q = q.eq('contact_phone', contact_phone);
    else if (contact_name) q = q.eq('contact_name', contact_name);
    else return res.status(400).json({ error: 'contact_name or contact_phone required' });
    await q;
    res.json({ success: true });
  } catch(e) {
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages/send', authMiddleware, smsSendLimiter, async (req, res) => {
  const { contact_name, contact_phone, contact_type, body } = req.body;
  if (!contact_phone || !body) return res.status(400).json({ error: 'Phone and message required' });
  try {
    const msg = await twilioClient.messages.create({ body, from: process.env.TWILIO_PHONE_NUMBER, to: contact_phone, statusCallback: `${PUBLIC_BASE_URL}/api/webhooks/sms-status` });
    const job_id = await findRelevantJobForPhone(contact_phone).catch(() => null);
    const { data } = await supabase.from('messages').insert({
      contact_name, contact_phone, contact_type, direction: 'out', body, twilio_sid: msg.sid, read: true, job_id,
      sent_by_user_id: req.user.id, sent_by_name: req.user.name
    }).select().single();
    await logAudit('message', data.id, req.user.id, req.user.name, 'sent', `Sent SMS to ${contact_name || contact_phone}`);
    broadcastNudge('new_message'); // other open dispatcher tabs see the sent message instantly too
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// MMS — accepts an actual uploaded file (image, PDF, etc.) from the browser,
// hosts it on Supabase Storage so it has a real public URL, then hands that
// URL to Twilio as media to attach. Twilio requires a reachable URL for MMS —
// it cannot accept raw file bytes directly, so this upload-then-link step is
// not optional, it's how MMS fundamentally works everywhere, not just here.
app.post('/api/messages/send-mms', authMiddleware, smsSendLimiter, upload.single('file'), async (req, res) => {
  const { contact_name, contact_phone, contact_type, body } = req.body;
  if (!contact_phone) return res.status(400).json({ error: 'Phone required' });
  if (!req.file) return res.status(400).json({ error: 'File required' });
  try {
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const fileName = `mms/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    const { error: uploadError } = await supabase.storage.from('message-media').upload(fileName, req.file.buffer, {
      contentType: req.file.mimetype, upsert: false
    });
    if (uploadError) return res.status(500).json({ error: 'Upload failed: ' + uploadError.message });
    const { data: urlData } = supabase.storage.from('message-media').getPublicUrl(fileName);
    const mediaUrl = urlData.publicUrl;

    const msg = await twilioClient.messages.create({
      body: body || '', from: process.env.TWILIO_PHONE_NUMBER, to: contact_phone, mediaUrl: [mediaUrl],
      statusCallback: `${PUBLIC_BASE_URL}/api/webhooks/sms-status`
    });
    const job_id = await findRelevantJobForPhone(contact_phone).catch(() => null);
    const { data } = await supabase.from('messages').insert({
      contact_name, contact_phone, contact_type, direction: 'out', body: body || '', twilio_sid: msg.sid, read: true, job_id,
      sent_by_user_id: req.user.id, sent_by_name: req.user.name, media_url: mediaUrl, media_type: req.file.mimetype
    }).select().single();
    await logAudit('message', data.id, req.user.id, req.user.name, 'sent_mms', `Sent MMS to ${contact_name || contact_phone}`);
    res.json(data);
  } catch(e) {
    console.error('/api/messages/send-mms error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Twilio webhook - incoming SMS
const CONFIRM_KEYWORDS = ['ok', 'okay', 'got it', 'gotit', 'confirmed', 'on it', 'onit', 'yes', 'yep', 'k', 'received', 'roger', 'sure', '👍'];
// ─── CLOSING MESSAGE DETECTION ──────────────────────────────────────────────────
// A real closing message from a tech looks like an address or ticket reference
// with a CHARGE at (usually) the end — a 2-4 digit amount with an explicit
// dollar sign: "433 market st camden 08102 done 250$" or "JOB-5787 $185 mb".
// A message needs an explicit dollar amount to even be CONSIDERED a closing —
// "$250", "250$", "250 $", "$1,250", decimals allowed. A number with no dollar
// sign is never a closing. (This alone stops zipcodes/years/phone fragments.)
const CLOSING_PATTERN = /\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\b|\b\d{1,4}(?:\.\d{1,2})?\s*\$/;

// ── QUOTE / UPDATE CONTEXT ──────────────────────────────────────────────────────
// The hard part Hassan flagged: a real closing ($ amount + address = job done)
// looks almost identical to a QUOTE UPDATE ("we quoted cx 250", "gave the
// customer 300", "estimate is 180"). Both carry a dollar amount, but a quote is
// NOT a closing — the money hasn't been collected, it's just a number the tech
// told the customer. We detect quote/estimate context by meaning, not one word:
// a family of quote verbs/nouns plus the common "to/for the customer" framing.
const QUOTE_CONTEXT = [
  // quote + synonyms/inflections
  'quote', 'quoted', 'quoting', 'quotes',
  'estimate', 'estimated', 'estimating', 'estimates', 'est',
  'price', 'priced', 'pricing',
  'gave', 'giving', 'give', 'told', 'telling', 'offer', 'offered', 'offering',
  'asking', 'asked', 'charge them', 'charging',
  // "quoted/gave THE CUSTOMER" framing — strong quote signal
  'to cx', 'the cx', 'for cx', 'gave cx', 'told cx', 'quoted cx',
  'to customer', 'the customer', 'for customer', 'to client', 'the client'
];
// Words that mean the money is actually IN — a real closing, which OVERRIDES a
// quote word if both somehow appear ("quoted 300, collected 250" → closing 250).
const COLLECTED_CONTEXT = ['collected', 'paid', 'cash', 'zelle', 'card', 'charged card', 'card charge', 'done', 'closed', 'closing', 'complete', 'completed', 'finished', 'got paid', 'received payment'];

// Returns the set of ways THIS tech might plausibly sign off a message with
// their own name/initials — full name, first name, and initials built from
// each word of their real name (e.g. "Mohamed B" -> "mb", "Musab" -> "musab").
// Deliberately scoped to a small, known set derived from the actual tech's own
// name, not any arbitrary short word, to keep false positives near zero.
function techSignoffTokens(techName) {
  if (!techName) return [];
  const parts = techName.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const tokens = new Set();
  tokens.add(parts.join(' '));
  if (parts[0]) tokens.add(parts[0]);
  if (parts.length > 1) tokens.add(parts.map(p => p[0]).join(''));
  return [...tokens];
}

// A closing without a dollar sign still needs to look like the real workflow:
// an address being resent, ending in the tech's own name/initials — not just
// any message that happens to contain a number or a short word.
function looksLikeAddressSignoff(bodyTrim, techName) {
  if (bodyTrim.length < 8 || bodyTrim.length > 200) return false;
  const hasAddressSignal = /\b\d{5}\b/.test(bodyTrim) || /\d+\s+[a-zA-Z]/.test(bodyTrim); // zip, or "123 Main"
  if (!hasAddressSignal) return false;
  const tokens = techSignoffTokens(techName);
  if (!tokens.length) return false;
  const lower = bodyTrim.toLowerCase();
  return tokens.some(t => new RegExp('(^|\\W)' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|\\W)').test(lower));
}

// Returns true if the message reads like a quote/estimate UPDATE rather than a
// completed job — meaning it should NOT be treated as a closing.
function looksLikeQuoteUpdate(bodyLower) {
  const hasQuoteWord = QUOTE_CONTEXT.some(w => new RegExp('(^|\\W)' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(\\W|$)').test(bodyLower));
  if (!hasQuoteWord) return false;
  // A collection word present alongside means it actually closed — not a quote.
  const hasCollected = COLLECTED_CONTEXT.some(w => new RegExp('(^|\\W)' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(\\W|$)').test(bodyLower));
  return !hasCollected;
}

// Parses a tech's closing message into structured pieces: total, parts cost, tech initials.
// Handles: "130$\n20p", "130\n20$part", "120$\njuan", "150mb" (treated as a flat total).
function parseClosingMessage(body) {
  const lines = body.split('\n').map(l => l.trim()).filter(Boolean);
  const hasDollarSign = /\$/.test(body);
  let total = null, parts = null, initials = null;
  for (const line of lines) {
    const partsMatch = line.match(/(\d+(?:\.\d+)?)\s*\$?\s*(p|part|parts)\b|(\d+(?:\.\d+)?)\$\s*(p|part|parts)\b/i);
    // The charge itself must carry a $ — "$250", "250$", "$1,250.50" all work.
    const dollarMatch = line.match(/\$\s*(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?)|(\d{1,4}(?:\.\d{1,2})?)\s*\$/);
    // A bare number line ("250" alone, or "250mb") only counts as the total when a
    // $ appears SOMEWHERE in the message (so we know it's finance talk), and only
    // for 2-4 digit amounts that don't look like a zipcode (no leading zero, max 4 digits).
    const plainNumberMatch = line.match(/^([1-9]\d{1,3}(?:\.\d{1,2})?)\s*(mb)?$/i);
    const wordMatch = line.match(/^[a-zA-Z]{2,}$/);
    if (partsMatch) {
      parts = parseFloat((partsMatch[1] || partsMatch[3] || '').replace(/,/g, ''));
    } else if (dollarMatch && total === null) {
      total = parseFloat((dollarMatch[1] || dollarMatch[2] || '').replace(/,/g, ''));
    } else if (plainNumberMatch && hasDollarSign && total === null) {
      total = parseFloat(plainNumberMatch[1]);
    } else if (wordMatch && !CONFIRM_KEYWORDS.includes(line.toLowerCase())) {
      initials = line;
    }
  }
  return { total, parts, initials };
}

// ─── INBOUND SELF-TEST ────────────────────────────────────────────────────────
// Open /api/webhooks/sms-selftest in a logged-in browser tab. It performs the
// EXACT same insert the real inbound webhook performs and returns the raw
// database result. Message appears in SMS page + returns ok:true → storage
// works and any missing inbound texts are a Twilio-side config issue (the
// Messaging Service isn't forwarding to our webhook). Returns an error → the
// database is rejecting inserts (missing column or RLS policy) and the error
// text says exactly why.
app.get('/api/webhooks/sms-selftest', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('messages').insert({
      contact_name: 'Webhook Self-Test', contact_phone: '+10000000000', contact_type: 'unknown',
      direction: 'in', body: 'Self-test inbound message created at ' + new Date().toISOString(), read: false,
      job_id: null, is_closing_attempt: false, closing_amount: null, closing_parts: null,
      closing_initials: null, media_url: null, media_type: null
    }).select().single();
    if (error) return res.json({ ok: false, layer: 'DATABASE', error: error.message, hint: 'The insert is being rejected. If the message mentions a missing column, run schema_sync.sql. If it mentions row-level security or policy, the messages table needs an anon INSERT policy.' });
    res.json({ ok: true, layer: 'DATABASE OK', stored_id: data.id, hint: 'Storage works. Check the SMS page for a "Webhook Self-Test" conversation. If real inbound texts still do not arrive, Twilio is not calling this server: fix the Messaging Service inbound setting.' });
  } catch(e) {
    res.json({ ok: false, layer: 'SERVER', error: e.message });
  }
});

app.post('/api/webhooks/sms', twilioWebhookAuth, async (req, res) => {
  try {
    const { From, Body, To } = req.body;
    // Find who sent it
    const { data: customer } = await supabase.from('customers').select('name').eq('phone', From).single();
    const { data: tech } = await supabase.from('users').select('id,name,was_unavailable').eq('phone', From).single();
    const contact_name = customer?.name || tech?.name || From;
    const contact_type = customer ? 'customer' : tech ? 'tech' : 'unknown';
    const bodyTrim = (Body || '').trim();
    const bodyLower = bodyTrim.toLowerCase();

    // Handles the SUBSCRIBE keyword for customers who text it in voluntarily
    // to confirm or re-enable SMS updates. Sends a confirmation reply and
    // records the opt-in timestamp.
    if (bodyLower === 'subscribe') {
      if (customer) {
        await supabase.from('customers').update({ sms_subscribed: true, sms_subscribed_at: new Date().toISOString() }).eq('phone', From);
      }
      await twilioClient.messages.create({
        body: `You're subscribed to SMS updates from Express Lock&Key. Msg & data rates may apply. Reply STOP to unsubscribe at any time.`,
        from: process.env.TWILIO_PHONE_NUMBER, to: From
      });
      await supabase.from('messages').insert({ contact_name, contact_phone: From, contact_type, direction: 'in', body: Body, read: true });
      res.set('Content-Type', 'text/xml');
      return res.send('<Response></Response>');
    }

    let job_id = null;
    let is_closing_attempt = false;
    let closing_amount = null;
    let closing_parts = null;
    let closing_initials = null;

    // ── SPEED: only the ONE lookup that determines job_id runs before the
    // insert. Everything else (tech status update, confirm/closing DB writes,
    // the tech-available alert) is real but doesn't need to block the message
    // from appearing — it's deferred to right after the response, fire-and-forget.
    let job = null, confirmHit = false, wasUnavailable = false;
    if (tech) {
      wasUnavailable = tech.was_unavailable;
      const { data: openJobs } = await supabase.from('jobs')
        .select('*').eq('tech_id', tech.id).in('status', ['assigned', 'in-progress'])
        .order('assigned_at', { ascending: false }).limit(1);
      job = openJobs?.[0] || null;

      if (job) {
        confirmHit = CONFIRM_KEYWORDS.some(k => {
          if (bodyLower === k) return true;
          if (k === '👍') return bodyTrim.includes('👍');
          if (k.length < 2) return false; // bare "k" only counts as the entire message
          return new RegExp('(^|\\W)' + k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|\\W)').test(bodyLower);
        });
        // Closing detection with quote-awareness:
        //   1. must carry a dollar amount (CLOSING_PATTERN)
        //   2. must NOT read like a quote/estimate update (looksLikeQuoteUpdate)
        // So "433 market st camden 08102 250$" → closing, but "we quoted cx 250$"
        // or "gave the customer 300" → NOT a closing (it's a quote update).
        if (CLOSING_PATTERN.test(bodyTrim) && bodyTrim.length < 200 && !looksLikeQuoteUpdate(bodyLower)) {
          is_closing_attempt = true;
          const parsed = parseClosingMessage(bodyTrim);
          closing_amount = parsed.total;
          closing_parts = parsed.parts;
          closing_initials = parsed.initials;
        } else if (!is_closing_attempt && looksLikeAddressSignoff(bodyTrim, tech.name)) {
          // Not every closing carries a dollar amount — some techs just resend
          // the address and sign off with their own name or initials (no price
          // at all, e.g. it was already agreed elsewhere). Scoped tightly to
          // THIS specific tech's own name/initials (not any arbitrary word) so
          // it doesn't fire on ordinary chat that happens to mention someone —
          // still needs address-like content alongside it, matching the real
          // resend-and-signoff pattern rather than a bare name anywhere.
          is_closing_attempt = true;
          const parsed = parseClosingMessage(bodyTrim);
          closing_amount = parsed.total; // likely null — flagged for manual review in the Closing queue
          closing_parts = parsed.parts;
          closing_initials = parsed.initials || tech.name;
        }
        const mentionsJobId = bodyLower.includes(String(job.id).toLowerCase());
        if (confirmHit || is_closing_attempt || mentionsJobId) job_id = job.id;
      }
    }

    // Twilio sends incoming MMS media as NumMedia + MediaUrl0/MediaContentType0
    // (indexed 0, 1, 2... for multiple attachments — we store just the first,
    // since the UI shows one attachment per message bubble). Twilio's media
    // URLs require auth to fetch directly, so we re-host on Supabase Storage
    // the same way outbound MMS does, keeping both directions consistent and
    // making the image visible in chat without needing Twilio credentials
    // baked into the frontend.
    let inboundMediaUrl = null, inboundMediaType = null;
    const numMedia = parseInt(req.body.NumMedia || '0');
    if (numMedia > 0 && req.body.MediaUrl0) {
      try {
        const mediaResp = await fetch(req.body.MediaUrl0, {
          headers: { 'Authorization': 'Basic ' + Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64') }
        });
        const mediaBuffer = Buffer.from(await mediaResp.arrayBuffer());
        const contentType = req.body.MediaContentType0 || 'image/jpeg';
        const ext = contentType.split('/')[1] || 'jpg';
        const fileName = `mms/in-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
        const { error: upErr } = await supabase.storage.from('message-media').upload(fileName, mediaBuffer, { contentType, upsert: false });
        if (!upErr) {
          const { data: urlData } = supabase.storage.from('message-media').getPublicUrl(fileName);
          inboundMediaUrl = urlData.publicUrl;
          inboundMediaType = contentType;
        }
      } catch(e) { console.error('Inbound MMS re-host error:', e.message); }
    }

    await supabase.from('messages').insert({ contact_name, contact_phone: From, contact_type, direction: 'in', body: Body, read: false, job_id, is_closing_attempt, closing_amount, closing_parts, closing_initials, media_url: inboundMediaUrl, media_type: inboundMediaType });

    // Push to every open dispatcher tab NOW — before anything else runs. This is
    // the moment that used to be 15-20 seconds away; now it's immediate.
    broadcastNudge('new_message');
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');

    // ── Deferred side-effects — real work, but none of it should hold up the
    // message appearing on screen, so it runs after the response is already sent.
    (async () => {
      try {
        if (tech) {
          await supabase.from('users').update({ last_active_at: new Date().toISOString(), was_unavailable: false, status: 'online' }).eq('id', tech.id);
          if (job) {
            await supabase.from('jobs').update({ last_tech_message_at: new Date().toISOString(), last_tech_message_by: tech.name }).eq('id', job.id);
            if (!job.confirmed_by_tech && confirmHit) {
              await supabase.from('jobs').update({ confirmed_by_tech: true, confirmed_at: new Date().toISOString() }).eq('id', job.id);
              broadcastNudge('jobs_changed');
            }
          }
          if (wasUnavailable) {
            const { data: stillOpen } = await supabase.from('jobs').select('id,title,job_type,status,customer_name,phone,address').eq('tech_id', tech.id).in('status', ['assigned', 'in-progress']);
            await createAlert('tech_available', {
              title: `${tech.name} is now available`,
              body: `${tech.name} is now available. Click to assign a job.${stillOpen?.length ? ` They still have ${stillOpen.length} open job(s) to follow up on.` : ''}`,
              tech_id: tech.id, tech_name: tech.name, severity: 'info',
              data: { open_jobs: stillOpen || [] }
            });
            broadcastNudge('alert');
          }
        }
        if (is_closing_attempt && tech) {
          await createAlert('closing_message', {
            title: `Closing message from ${tech.name}`,
            body: `${tech.name} sent what looks like a closing/charge message for ${job_id}: "${bodyTrim}"`,
            tech_id: tech.id, tech_name: tech.name, job_id, severity: 'info',
            data: { message: bodyTrim, amount: closing_amount, parts: closing_parts, initials: closing_initials }
          });
          broadcastNudge('alert');
        }
        await createNotification('new_message', `New message from ${contact_name}`, Body);
        broadcastNudge('notification');
      } catch(e) { console.error('SMS webhook deferred work error:', e.message); }
    })();
  } catch(e) {
    console.error('SMS webhook error:', e.message);
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>'); // Twilio just needs a 200 + valid TwiML, even on our internal failure
  }
});

// Masked call - initiate via Twilio
// ─── SETTINGS ─────────────────────────────────────────────────────────────────

app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('settings').select('*');
    if (error) return res.status(500).json({ error: error.message });
    const obj = {};
    data.forEach(s => obj[s.key] = s.value);
    // Always reflect the live Railway env var, not a stale database value —
    // this is the actual source of truth and updates the instant Railway's
    // variable changes, with zero need to manually re-sync a settings row.
    obj.twilio_number = process.env.TWILIO_PHONE_NUMBER || obj.twilio_number || '';
    res.json(obj);
  } catch(e) {
    console.error('/api/settings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Public — no auth. Exposes only the Maps key (set in Railway env vars, never the
// database), so both the logged-in CRM and the public booking page can use address
// autocomplete with zero added latency (browser talks to Google directly).
app.get('/api/config/maps-key', authMiddleware, (req, res) => {
  res.json({ key: process.env.GOOGLE_MAPS_API_KEY || null });
});

app.get('/api/config/business-info', async (req, res) => {
  try {
    const { data } = await supabase.from('settings').select('key,value').in('key', ['business_name', 'business_phone', 'business_email']);
    const map = {}; data?.forEach(s => map[s.key] = s.value);
    res.json({ name: map.business_name || 'Express Lock&Key', phone: map.business_phone || '', email: map.business_email || '' });
  } catch(e) { res.json({ name: 'Express Lock&Key', phone: '', email: '' }); }
});

// Public — no auth. Real opt-in submissions for SMS consent, used as the
// actual documented proof of consent carriers/Twilio require for A2P 10DLC
// registration. Every submission is timestamped and stored — this is the
// genuine record, not just a UI gesture.
app.post('/api/sms-optin', smsOptinLimiter, async (req, res) => {
  try {
    const { name, phone, consented } = req.body;
    if (!name || !phone || !consented) return res.status(400).json({ error: 'Name, phone, and consent are required' });
    const { data, error } = await supabase.from('sms_optins').insert({
      name, phone, consented: true, consented_at: new Date().toISOString(),
      ip_address: req.ip || req.headers['x-forwarded-for'] || null
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    const { data: existing } = await supabase.from('customers').select('id').eq('phone', phone).single();
    if (!existing) await supabase.from('customers').insert({ name, phone, sms_opted_in: true });
    else await supabase.from('customers').update({ sms_opted_in: true }).eq('id', existing.id);
    // Real welcome message — this is the actual SMS sent the moment someone
    // submits the web opt-in form, not just a claim in the registration text.
    try {
      await twilioClient.messages.create({
        body: `Welcome to Express Lock&Key! You're now signed up to receive SMS updates about your service appointments, job updates, and receipts. Msg & data rates may apply. Reply STOP to unsubscribe at any time, HELP for help.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });
    } catch(smsErr) {
      console.error('Welcome SMS send failed:', smsErr.message); // don't fail the whole signup just because the welcome text didn't go out
    }
    res.json({ success: true, id: data.id });
  } catch(e) {
    console.error('/api/sms-optin error:', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/settings', authMiddleware, adminOnly, async (req, res) => {
  try {
  const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      await supabase.from('settings').upsert({ key, value, updated_at: new Date().toISOString() });
    }
    res.json({ success: true });
  } catch(e) {
    console.error('/api/settings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('notifications').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/notifications error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
  await supabase.from('notifications').update({ read: true }).eq('read', false);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/notifications/read-all error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── REPORTS ──────────────────────────────────────────────────────────────────

app.get('/api/reports/weekly', authMiddleware, requirePerm('perm_view_reports'), async (req, res) => {
  try {
  const offset = parseInt(req.query.offset) || 0;
    const d = nowInBusinessTz();
    d.setDate(d.getDate() + offset * 7);
    const day = d.getDay();
    const mon = new Date(d); mon.setDate(d.getDate() - day + 1);
    const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
    const monStr = dateInBusinessTz(mon);
    const sunStr = dateInBusinessTz(sun);
    let canSeeRevenue = req.user.role === 'admin';
    if (!canSeeRevenue) {
      const { data: u } = await supabase.from('users').select('perm_view_total_revenue').eq('id', req.user.id).single();
      canSeeRevenue = u?.perm_view_total_revenue === true;
    }
    const { data: jobs } = await supabase.from('jobs').select('*').gte('job_date', monStr).lte('job_date', sunStr);
    const { data: invoices } = await supabase.from('invoices').select('*').gte('invoice_date', monStr).lte('invoice_date', sunStr);
    const { data: techs } = await supabase.from('users').select('*').eq('role', 'tech');
    // Closing-first: the job closing is the revenue record; paid invoices only
    // count for legacy jobs without one.
    const rev = jobRevenueResolver(jobs, invoices);
    const techStats = techs?.map(t => {
      const tJobs = jobs?.filter(j => j.tech_id === t.id) || [];
      const revenue = tJobs.reduce((a, j) => a + rev.forJob(j.id), 0);
      return { tech: t, jobs_assigned: tJobs.length, jobs_completed: tJobs.filter(j => j.status === 'done').length, revenue, completion_rate: tJobs.length ? Math.round(tJobs.filter(j => j.status === 'done').length / tJobs.length * 100) : 0 };
    });
    res.json({
      week_start: monStr, week_end: sunStr, total_jobs: jobs?.length || 0, completed_jobs: jobs?.filter(j => j.status === 'done').length || 0,
      total_revenue: canSeeRevenue ? ((jobs || []).reduce((a, j) => a + rev.forJob(j.id), 0)) : null,
      outstanding: canSeeRevenue ? (invoices?.filter(i => i.status === 'unpaid' && !rev.hasClosing(i.job_id)).reduce((a, i) => a + (i.total || 0), 0) || 0) : null,
      tech_stats: techStats || []
    });
  } catch(e) {
    console.error('/api/reports/weekly error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── CUSTOM COMMISSION REPORT ───────────────────────────────────────────────────
// Shows actual commission paid per tech over a date range, broken down by which
// tier/rule fired on each invoice — since techs can have different rates below
// vs above a job-value threshold. Lets Hassan verify the right rate applied to
// the right jobs, not just see a single blended commission number.
app.get('/api/reports/commission', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { tech_id, start_date, end_date } = req.query;
    const invoices = await fetchAllRows(() => {
      let q = supabase.from('invoices').select('*').order('invoice_date', { ascending: false });
      if (tech_id) q = q.eq('tech_id', tech_id);
      if (start_date) q = q.gte('invoice_date', start_date);
      if (end_date) q = q.lte('invoice_date', end_date);
      return q;
    });
    const error = null;
    if (error) return res.status(500).json({ error: error.message });

    const { data: techs } = await supabase.from('users').select('id,name,default_commission_type,default_commission_value,commission_rules').eq('role', 'tech');
    const techMap = {}; (techs || []).forEach(t => techMap[t.id] = t);

    // ── CLOSINGS FIRST ── The job closing (total / parts / tech rate) is the
    // commission record. Invoices only feed this report for legacy jobs that
    // have no closing, so history stays intact while all new work runs through
    // the closing section.
    const closedJobs = await fetchAllRows(() => {
      let q = supabase.from('jobs').select('*').not('closing_total', 'is', null);
      if (tech_id) q = q.eq('tech_id', tech_id);
      if (start_date) q = q.gte('job_date', start_date);
      if (end_date) q = q.lte('job_date', end_date);
      return q;
    });
    const closedJobIds = new Set((closedJobs || []).map(j => j.id));

    const byTech = {};
    const ensureTech = (techId, techName) => {
      if (!byTech[techId]) byTech[techId] = { tech_id: techId, tech_name: techName, tiers: {}, total_commission: 0, total_jobs: 0, total_subtotal: 0 };
      return byTech[techId];
    };

    for (const job of closedJobs || []) {
      if (!job.tech_id) continue;
      const entry = ensureTech(job.tech_id, job.tech_name || techMap[job.tech_id]?.name || 'Unknown');
      const laborBasis = (parseFloat(job.closing_total) || 0) - (parseFloat(job.closing_parts) || 0);
      entry.total_jobs++;
      entry.total_commission += parseFloat(job.closing_commission_amount) || 0;
      entry.total_subtotal += laborBasis;
      const tierKey = job.closing_commission_type === 'flat' ? `Flat $${job.closing_commission_value}` : `${job.closing_commission_value}% of labor`;
      if (!entry.tiers[tierKey]) entry.tiers[tierKey] = { label: tierKey, rate_type: job.closing_commission_type, rate_value: job.closing_commission_value, job_count: 0, commission_total: 0, subtotal_total: 0 };
      entry.tiers[tierKey].job_count++;
      entry.tiers[tierKey].commission_total += parseFloat(job.closing_commission_amount) || 0;
      entry.tiers[tierKey].subtotal_total += laborBasis;
    }

    // ── LEGACY INVOICES ── only for jobs without a closing record.
    for (const inv of invoices || []) {
      if (!inv.tech_id) continue;
      if (inv.job_id && closedJobIds.has(inv.job_id)) continue; // closing supersedes
      const entry = ensureTech(inv.tech_id, inv.tech_name || techMap[inv.tech_id]?.name || 'Unknown');
      entry.total_jobs++;
      entry.total_commission += inv.tech_commission_amount || 0;
      entry.total_subtotal += inv.subtotal || 0;
      const ruleApplied = inv.commission_rule_applied;
      const tierKey = ruleApplied ? `${ruleApplied.operator} $${ruleApplied.amount}` : 'Default rate (invoice)';
      if (!entry.tiers[tierKey]) entry.tiers[tierKey] = { label: tierKey, rate_type: inv.tech_commission_type, rate_value: inv.tech_commission_value, job_count: 0, commission_total: 0, subtotal_total: 0 };
      entry.tiers[tierKey].job_count++;
      entry.tiers[tierKey].commission_total += inv.tech_commission_amount || 0;
      entry.tiers[tierKey].subtotal_total += inv.subtotal || 0;
    }

    const result = Object.values(byTech).map(entry => ({
      ...entry,
      tiers: Object.values(entry.tiers).sort((a, b) => b.job_count - a.job_count),
      avg_job_value: entry.total_jobs ? Math.round((entry.total_subtotal / entry.total_jobs) * 100) / 100 : 0
    })).sort((a, b) => b.total_commission - a.total_commission);

    res.json({ report: result, total_commission_paid: result.reduce((a, t) => a + t.total_commission, 0) });
  } catch(e) {
    console.error('/api/reports/commission error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/reports/export', authMiddleware, async (req, res) => {
  try {
  const { tech_id, start_date, end_date } = req.query;
    const invoices = await fetchAllRows(() => {
      let q = supabase.from('invoices').select('*');
      if (tech_id) q = q.eq('tech_id', tech_id);
      if (start_date) q = q.gte('invoice_date', start_date);
      if (end_date) q = q.lte('invoice_date', end_date);
      return q;
    });
    // Every field is properly quoted (a customer name containing a comma used to
    // shift every column after it), and values starting with = + - @ get a leading
    // apostrophe so Excel/Sheets treat them as text, not live formulas (CSV injection).
    const csvField = (v) => {
      let str = v === null || v === undefined ? '' : String(v);
      if (/^[=+\-@]/.test(str)) str = "'" + str;
      return '"' + str.replace(/"/g, '""') + '"';
    };
    const csv = ['Invoice #,Job,Customer,Tech,Subtotal,Tax,Total,Status,Date',
      ...(invoices || []).map(i => [i.id, i.job_id || '', i.customer_name || '', i.tech_name || '', i.subtotal || 0, i.tax_amount || 0, i.total || 0, i.status, i.invoice_date].map(csvField).join(','))
    ].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=fieldpro-report.csv');
    res.send(csv);
  } catch(e) {
    console.error('/api/reports/export error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Helper
async function createNotification(type, title, body) {
  await supabase.from('notifications').insert({ type, title, body });
}

// ─── ADMIN MULTI-CHANNEL REPORTING ─────────────────────────────────────────────
// Sends Hassan's own operational reports (alert mirrors, job-assignment audits)
// through up to 3 channels: WhatsApp first, SMS fallback if WhatsApp fails,
// and Discord webhook (independent — fires regardless of WhatsApp/SMS outcome,
// since it's free and a good permanent log). Each channel is optional —
// if its setting is blank, it's simply skipped.
async function sendAdminReport(type, message) {
  const { data: s } = await supabase.from('settings').select('key,value');
  const settings = {}; s?.forEach(x => settings[x.key] = x.value);
  const waNumber = settings.admin_report_whatsapp_number;
  const smsNumber = settings.admin_report_sms_number;
  const discordWebhook = settings.admin_report_discord_webhook;

  let whatsappOk = false;
  if (waNumber) {
    try {
      const waFrom = settings.whatsapp_from || 'whatsapp:+14155238886';
      const waTo = waNumber.startsWith('whatsapp:') ? waNumber : `whatsapp:${waNumber}`;
      await twilioClient.messages.create({ body: message, from: waFrom, to: waTo });
      whatsappOk = true;
      await supabase.from('admin_report_log').insert({ type, channel: 'whatsapp', message, status: 'sent' });
    } catch(e) {
      await supabase.from('admin_report_log').insert({ type, channel: 'whatsapp', message, status: 'failed', error: e.message });
    }
  }

  if (!whatsappOk && smsNumber) {
    try {
      await twilioClient.messages.create({ body: message, from: process.env.TWILIO_PHONE_NUMBER, to: smsNumber });
      await supabase.from('admin_report_log').insert({ type, channel: 'sms', message, status: 'sent' });
    } catch(e) {
      await supabase.from('admin_report_log').insert({ type, channel: 'sms', message, status: 'failed', error: e.message });
    }
  }

  if (discordWebhook) {
    try {
      const r = await fetch(discordWebhook, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: message }) });
      await supabase.from('admin_report_log').insert({ type, channel: 'discord', message, status: r.ok ? 'sent' : 'failed', error: r.ok ? null : `HTTP ${r.status}` });
    } catch(e) {
      await supabase.from('admin_report_log').insert({ type, channel: 'discord', message, status: 'failed', error: e.message });
    }
  }
}

// ─── ALERT ENGINE ──────────────────────────────────────────────────────────────
// Alerts are a richer cousin of notifications — they carry structured `data`
// (lists of job ids, mismatches, etc.) so the frontend can render an actionable
// popup instead of a plain toast. They're also de-duplicated so we don't spam.

async function getSettingsMap() {
  const { data } = await supabase.from('settings').select('key,value');
  const obj = {}; data?.forEach(s => obj[s.key] = s.value);
  return obj;
}

// ─── MESSAGE TEMPLATES ──────────────────────────────────────────────────────────
// Lets the admin customize the wording of tech reminders, dispatch alerts, and
// customer messages from Settings, without needing a code change. Falls back to
// a sensible default if the template key isn't set. {placeholders} are filled
// from the data object passed in — any key not present is left blank.
async function renderTemplate(templateKey, data, fallback) {
  const settings = await getSettingsMap();
  const template = settings[templateKey] || fallback || '';
  return template.replace(/\{(\w+)\}/g, (_, key) => (data[key] !== undefined && data[key] !== null) ? String(data[key]) : '');
}

// Builds and sends the full appointment reminder "ticket" to the assigned tech,
// respecting the admin's field-visibility checklist (tpl_reminder_fields) and
// custom template (tpl_appointment_reminder_tech). call_extension is a placeholder
// today (admin/dispatch place masked calls from the CRM) — Phase 7 will add a real
// dial-in extension per job so the tech can call the customer directly.
async function sendAppointmentReminderTicket(job) {
  const settings = await getSettingsMap();
  const { data: tech } = await supabase.from('users').select('phone').eq('id', job.tech_id).single();
  if (!tech?.phone) return;
  let fieldVisibility = {};
  try { fieldVisibility = JSON.parse(settings.tpl_reminder_fields || '{}'); } catch(e) {}
  // Make sure this job has an active extension to call the customer through —
  // jobs scheduled long in advance may have had theirs expire by reminder time.
  const ext = fieldVisibility.call_extension !== false ? await allocateExtension(job.id) : null;
  const data = {
    job_id: job.id,
    customer_name: fieldVisibility.customer_name !== false ? job.customer_name : '',
    job_type: fieldVisibility.job_type !== false ? (job.job_type || job.title || '') : '',
    address: fieldVisibility.address !== false ? (job.address || '') : '',
    phone: fieldVisibility.phone === true ? (job.phone || '') : '',
    scheduled_time: fieldVisibility.scheduled_time !== false ? new Date(job.scheduled_date).toLocaleString('en-US', { timeZone: BUSINESS_TZ }) : '',
    notes: fieldVisibility.notes === true ? (job.notes || '') : '',
    call_extension: ext ? `Call ${settings.twilio_number || process.env.TWILIO_PHONE_NUMBER}, enter ext ${ext} to reach customer` : ''
  };
  const fallback = 'APPOINTMENT REMINDER\nJob: {job_id}\nCustomer: {customer_name}\nService: {job_type}\nAddress: {address}\nTime: {scheduled_time}\n{call_extension}';
  const message = await renderTemplate('tpl_appointment_reminder_tech', data, fallback);
  try { await twilioClient.messages.create({ body: message, from: process.env.TWILIO_PHONE_NUMBER, to: tech.phone }); } catch(e) { console.log('Reminder SMS error:', e.message); }
}

async function alertsEnabled(settings, key) {
  return settings[key] !== 'false'; // default ON unless explicitly turned off
}

async function createAlert(type, { title, body, job_id = null, tech_id = null, tech_name = null, severity = 'info', data = {}, dedupeWindowMinutes = 30 }) {
  // Avoid duplicate alerts of the same type+job within a window
  if (job_id) {
    const cutoff = new Date(Date.now() - dedupeWindowMinutes * 60000).toISOString();
    const { data: existing } = await supabase.from('alerts').select('id').eq('type', type).eq('job_id', job_id).gte('created_at', cutoff).eq('resolved', false).limit(1);
    if (existing && existing.length) return null;
  }
  // The insert's error was previously DISCARDED — if the alerts table was
  // missing any column this insert needs, every alert creation failed silently
  // forever: empty table, no popups, no log line, nothing. This is the bug that
  // made alerts appear "broken" no matter how many times the popup UI was fixed.
  const { data: alert, error: insErr } = await supabase.from('alerts').insert({ type, job_id, tech_id, tech_name, title, body, data, severity }).select().single();
  if (insErr) {
    console.error('createAlert INSERT FAILED (' + type + '):', insErr.message, '— run the latest migration; the alerts table is likely missing columns');
    return null;
  }
  broadcastNudge('alert'); // popup appears on every open dispatcher tab within ~1s
  // NO bell mirror. Alerts exist ONLY as blocking warning dialogs — per Hassan:
  // an alert that can sit unseen in a notification list is not an alert. The
  // bell is for informational events; alerts interrupt.
  // Mirror to admin's own WhatsApp/SMS/Discord, so Hassan sees what dispatch sees, live.
  const { data: mirrorSetting } = await supabase.from('settings').select('value').eq('key', 'admin_report_mirror_alerts').single();
  if (mirrorSetting?.value !== 'false') {
    sendAdminReport('alert_mirror', `🔔 ${title}\n${body}`).catch(() => {});
  }
  return alert;
}

// Runs all time-based alert checks. Safe to call repeatedly (every few minutes).
async function runAlertChecks() {
  const settings = await getSettingsMap();
  const noRespMin = parseInt(settings.alert_tech_no_response_minutes || '15');
  const staleHours = parseFloat(settings.alert_stale_job_hours || '2');
  const apptHours = parseFloat(settings.alert_appointment_reminder_hours || '1');

  // 1) Tech didn't respond to assigned job within N minutes
  if (await alertsEnabled(settings, 'alert_tech_no_response')) {
    const cutoff = new Date(Date.now() - noRespMin * 60000).toISOString();
    const { data: unconfirmed } = await supabase.from('jobs').select('*')
      .eq('confirmed_by_tech', false).not('tech_id', 'is', null).not('assigned_at', 'is', null)
      .lte('assigned_at', cutoff).in('status', ['assigned']);
    for (const job of unconfirmed || []) {
      const { data: unassigned } = await supabase.from('jobs').select('id,title,job_type,customer_name,phone,address').eq('status', 'new');
      await createAlert('tech_no_response', {
        title: `${job.tech_name} hasn't confirmed ${job.id}`,
        body: `Warning: job ${job.id} assigned to ${job.tech_name} has not been received or confirmed yet.${unassigned?.length ? ` ${unassigned.length} job(s) still unassigned.` : ''}`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'warning',
        data: { unassigned_jobs: unassigned || [] }
      });
      runEventWorkflows('no_response', job).catch(() => {});
    }
  }

  // 2) Stale job — no appointment set & no status change in N hours (recurring until closed/cancelled)
  if (await alertsEnabled(settings, 'alert_stale_job')) {
    const { data: openJobs } = await supabase.from('jobs').select('*').not('status', 'in', '("done","cancelled")');
    const now = Date.now();
    for (const job of openJobs || []) {
      const refTime = job.scheduled_date ? new Date(job.scheduled_date).getTime() : new Date(job.created_at).getTime();
      const hoursSince = (now - refTime) / 3600000;
      if (hoursSince < staleHours) continue;
      const lastAlert = job.last_stale_alert_at ? new Date(job.last_stale_alert_at).getTime() : 0;
      const hoursSinceLastAlert = (now - lastAlert) / 3600000;
      if (hoursSinceLastAlert < staleHours) continue; // only re-fire once per interval
      await createAlert('stale_job', {
        title: `Stale job ${job.id}`,
        body: `Stale job ${job.id} has had no updates for ${staleHours}+ hours.`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'warning',
        dedupeWindowMinutes: 1 // we control re-fire ourselves via last_stale_alert_at
      });
      await supabase.from('jobs').update({ last_stale_alert_at: new Date().toISOString(), stale_alert_count: (job.stale_alert_count || 0) + 1 }).eq('id', job.id);
    }
  }

  // 3) Appointment reminder — N hours before scheduled time, once.
  // Also sends the tech a full reminder "ticket" by SMS, using the customizable
  // template + field checklist from Settings, so they get exactly the info Hassan wants.
  if (await alertsEnabled(settings, 'alert_appointment_reminder')) {
    const now = new Date();
    const windowEnd = new Date(now.getTime() + apptHours * 3600000);
    const { data: upcoming, error: apptErr } = await supabase.from('jobs').select('*')
      .eq('appointment_reminder_sent', false).not('scheduled_date', 'is', null)
      .gte('scheduled_date', now.toISOString()).lte('scheduled_date', windowEnd.toISOString())
      .not('status', 'in', '("done","cancelled")');
    if (apptErr) console.error('Appointment reminder query failed:', apptErr.message, '— check that appointment_reminder_sent exists on jobs (run the latest migration)');
    for (const job of upcoming || []) {
      await createAlert('appointment_reminder', {
        title: `Upcoming appointment — ${job.id}`,
        body: `Upcoming appointment: ${job.id} is scheduled for ${new Date(job.scheduled_date).toLocaleString('en-US', { timeZone: BUSINESS_TZ })} with ${job.tech_name || 'unassigned tech'}.`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'info'
      });
      if (job.tech_id) await sendAppointmentReminderTicket(job);
      await supabase.from('jobs').update({ appointment_reminder_sent: true }).eq('id', job.id);
    }
  }

  // 5) Recurring workflows — re-fire every interval_minutes for open jobs matching
  // the trigger condition, up to max_repeats, until the job is done/cancelled.
  const { data: recurringWfs } = await supabase.from('workflows').select('*').eq('trigger_type', 'recurring').eq('active', true);
  for (const wf of (recurringWfs || [])) {
    const cond = wf.trigger_condition || {};
    const intervalMin = parseInt(cond.interval_minutes) || 30;
    const maxRepeats = cond.max_repeats != null ? parseInt(cond.max_repeats) : null;
    const last = wf.last_run ? new Date(wf.last_run) : new Date(0);
    if ((Date.now() - last.getTime()) / 60000 < intervalMin) continue;
    if (maxRepeats != null && (wf.run_count || 0) >= maxRepeats) continue;
    const { data: openJobs } = await supabase.from('jobs').select('*').not('status', 'in', '("done","cancelled")');
    let firedAny = false;
    for (const job of openJobs || []) {
      if (!workflowConditionMatches(cond, job)) continue;
      const { data: tech } = job.tech_id ? await supabase.from('users').select('phone').eq('id', job.tech_id).single() : { data: null };
      await executeWorkflowActions(wf.actions, { ...job, tech_phone: tech?.phone || null });
      firedAny = true;
    }
    if (firedAny) await supabase.from('workflows').update({ run_count: (wf.run_count || 0) + 1, last_run: new Date().toISOString() }).eq('id', wf.id);
  }

  // 6) Expire stale call extensions, freeing them for reuse
  await expireStaleExtensions().catch(() => {});

  // 7) Mark techs "unavailable" if no SMS activity in a while, so the next message
  // they send triggers the "now available" alert.
  const inactivityCutoff = new Date(Date.now() - 60 * 60000).toISOString(); // 60 min of silence = unavailable
  await supabase.from('users').update({ was_unavailable: true, status: 'offline' })
    .eq('role', 'tech').eq('was_unavailable', false).lt('last_active_at', inactivityCutoff);
}

// Self-contained interval — no external cron needed. Runs every N minutes (default 5).
let alertIntervalHandle = null;
async function startAlertEngine() {
  const settings = await getSettingsMap();
  const minutes = parseInt(settings.alert_check_interval_minutes || '5');
  if (alertIntervalHandle) clearInterval(alertIntervalHandle);
  alertIntervalHandle = setInterval(() => { runAlertChecks().catch(e => console.error('Alert check error:', e.message)); }, minutes * 60000);
  runAlertChecks().catch(e => console.error('Alert check error:', e.message));
}

// ─── ALERT API ROUTES ──────────────────────────────────────────────────────────

// Fires a real test alert through the real createAlert path — the definitive
// end-to-end check for the popup pipeline. Admin only. Returns the exact
// failure detail if creation fails, instead of failing silently.
app.post('/api/alerts/test', authMiddleware, adminOnly, async (req, res) => {
  try {
    const alert = await createAlert('stale_job', {
      title: 'Test Alert — popup pipeline check',
      body: 'This is a test alert fired by an admin. Take an action or Skip — both should work, and Skip should bring it back in 5 minutes.',
      severity: req.body?.severity || 'warning',
      dedupeWindowMinutes: 0
    });
    if (!alert) return res.status(500).json({ error: 'createAlert returned null — check Railway logs for "createAlert INSERT FAILED" to see the exact database error' });
    res.json({ success: true, alert_id: alert.id });
  } catch(e) {
    console.error('/api/alerts/test error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/alerts', authMiddleware, async (req, res) => {
  try {
  // Unresolved AND not snoozed. "Skip" on the popup snoozes an alert for a set
  // window instead of resolving it — it comes back if the situation persists.
  const { data, error } = await supabase.from('alerts').select('*').eq('resolved', false).or('snoozed_until.is.null,snoozed_until.lt.' + new Date().toISOString()).order('created_at', { ascending: false }).limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/alerts error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/alerts/:id/read', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('alerts').update({ read: true }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/alerts/:id/read error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/alerts/:id/resolve', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('alerts').update({ resolved: true, read: true }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/alerts/:id/resolve error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// "Skip" from the alert popup: hides this alert for `minutes` (default 60) without
// resolving it. If the underlying problem is still there after the window, the
// alert pops again — skipping is a snooze, never a permanent dismissal.
app.put('/api/alerts/:id/snooze', authMiddleware, async (req, res) => {
  try {
    const minutes = Math.min(Math.max(parseInt(req.body?.minutes) || 60, 5), 1440);
    const until = new Date(Date.now() + minutes * 60000).toISOString();
    const { error } = await supabase.from('alerts').update({ snoozed_until: until }).eq('id', req.params.id);
    if (error) { console.error('/api/alerts/:id/snooze error:', error.message); return res.status(500).json({ error: 'Server error' }); }
    res.json({ success: true, snoozed_until: until });
  } catch(e) {
    console.error('/api/alerts/:id/snooze error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── CLOSING MESSAGES REVIEW PANEL ─────────────────────────────────────────────
// Every tech message flagged as a closing/charge attempt, joined with job context,
// so admin can see at a glance: was it actually closed? on the right tech? what amount?

app.get('/api/closing-messages', authMiddleware, adminOnly, async (req, res) => {
  try {
  const filter = req.query.filter || 'all'; // all, pending, mismatched, closed
    let query = supabase.from('messages').select('*').eq('is_closing_attempt', true).order('created_at', { ascending: false }).limit(100);
    if (filter === 'pending') query = query.eq('closing_reviewed', false);
    const { data: msgs, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    // Attach job context for each message
    const jobIds = [...new Set((msgs || []).map(m => m.job_id).filter(Boolean))];
    const { data: jobs } = jobIds.length ? await supabase.from('jobs').select('*').in('id', jobIds) : { data: [] };
    const jobsById = {}; (jobs || []).forEach(j => jobsById[j.id] = j);

    const enriched = (msgs || []).map(m => {
      const job = jobsById[m.job_id];
      const mismatched = job && job.last_tech_message_by && job.tech_name && job.last_tech_message_by !== job.tech_name;
      return {
        ...m,
        job_title: job?.title || job?.job_type || null,
        job_status: job?.status || null,
        job_address: job?.address || null,
        assigned_tech: job?.tech_name || null,
        is_closed: job?.status === 'done',
        is_mismatched: !!mismatched,
        invoice_id: job?.invoice_id || null
      };
    });

    const filtered = filter === 'mismatched' ? enriched.filter(m => m.is_mismatched)
      : filter === 'closed' ? enriched.filter(m => m.is_closed)
      : enriched;

    res.json(filtered);
  } catch(e) {
    console.error('/api/closing-messages error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/closing-messages/:id/review', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('messages').update({ closing_reviewed: true }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('closing_message', req.params.id, req.user.id, req.user.name, 'reviewed', `Marked closing message reviewed`);
    res.json(data);
  } catch(e) {
    console.error('/api/closing-messages/:id/review error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/closing-messages/:id/amount', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { amount } = req.body;
    const { data, error } = await supabase.from('messages').update({ closing_amount: amount }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('closing_message', req.params.id, req.user.id, req.user.name, 'amount_corrected', `Corrected closing amount to $${amount}`);
    res.json(data);
  } catch(e) {
    console.error('/api/closing-messages/:id/amount error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/alerts/run-checks', async (req, res) => {
  // Manual/external trigger — requires x-cron-secret header matching CRON_SECRET env var.
  // Previously only checked the secret if CRON_SECRET was set, meaning a missing env var
  // left this endpoint completely open. Now always requires the secret.
  const secret = req.headers['x-cron-secret'];
  if (!process.env.CRON_SECRET || secret !== process.env.CRON_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  try { await runAlertChecks(); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});


// ─── TICKET HISTORY ───────────────────────────────────────────────────────────

async function logHistory(job_id, user_id, user_name, action, field_changed='', old_value='', new_value='') {
  await supabase.from('ticket_history').insert({ job_id, user_id, user_name, action, field_changed, old_value, new_value });
}

// General-purpose "who did what" log — covers entities ticket_history can't
// (messages, invoices, closing message reviews), since those aren't always
// tied to a single job_id the way ticket history is. Failures here are
// deliberately swallowed (.catch) since a logging failure should never block
// the actual action the user is trying to take.
async function logAudit(entityType, entityId, userId, userName, action, details = '') {
  try {
    await supabase.from('audit_log').insert({ entity_type: entityType, entity_id: entityId, user_id: userId, user_name: userName, action, details });
  } catch(e) { console.error('logAudit error:', e.message); }
}

// ─── COMMISSION RESOLVER ───────────────────────────────────────────────────────
// Given a tech and an invoice subtotal, figures out which commission to apply.
// Checks conditional rules first (in order, first match wins), falls back to the
// tech's default rate if no rule matches or none are configured.
function resolveCommission(tech, subtotal) {
  const rules = tech?.commission_rules || [];
  for (const rule of rules) {
    const amt = parseFloat(rule.amount);
    let matches = false;
    if (rule.operator === 'below' && subtotal < amt) matches = true;
    else if (rule.operator === 'at_or_above' && subtotal >= amt) matches = true;
    else if (rule.operator === 'above' && subtotal > amt) matches = true;
    else if (rule.operator === 'at_or_below' && subtotal <= amt) matches = true;
    if (matches) {
      return { type: rule.type, value: parseFloat(rule.value), rule_applied: rule };
    }
  }
  return { type: tech?.default_commission_type || 'percentage', value: parseFloat(tech?.default_commission_value) || 0, rule_applied: null };
}

function calcCommissionAmount(type, value, subtotal) {
  return type === 'percentage' ? subtotal * (value / 100) : value;
}

// Generates (or reuses) an unguessable token for an invoice's public receipt page.
const crypto = require('crypto');
async function ensureReceiptToken(invoiceId) {
  const { data: inv } = await supabase.from('invoices').select('receipt_token').eq('id', invoiceId).single();
  if (inv?.receipt_token) return inv.receipt_token;
  const token = crypto.randomBytes(16).toString('hex');
  await supabase.from('invoices').update({ receipt_token: token }).eq('id', invoiceId);
  return token;
}

// Lets the frontend preview which commission would apply before creating the invoice
// ─── JOB CLOSING — the system's financial record for a job ─────────────────────
// Fields: job total charge, parts charge, and the technician's specific rate
// (percentage or flat $). Commission math (shown live in the UI as well):
//   percentage → commission = rate% × (total − parts)   [labor basis]
//   flat $     → commission = the flat amount
// This record is completely separate from customer invoices: tweaking an
// invoice's presentation (labor/parts lines for a customer who wants a
// breakdown) NEVER changes these numbers.
app.put('/api/jobs/:id/closing', authMiddleware, requirePerm('perm_edit_jobs'), async (req, res) => {
  try {
    const total = parseFloat(req.body.total);
    const parts = parseFloat(req.body.parts) || 0;
    const cType = req.body.commission_type === 'flat' ? 'flat' : 'percentage';
    const cValue = parseFloat(req.body.commission_value) || 0;
    if (!isFinite(total) || total < 0) return res.status(400).json({ error: 'Job total charge is required' });
    if (parts < 0 || parts > total) return res.status(400).json({ error: 'Parts charge must be between 0 and the job total' });
    const commissionAmount = Math.round((cType === 'percentage' ? (total - parts) * (cValue / 100) : cValue) * 100) / 100;
    const { data: job, error } = await supabase.from('jobs').update({
      closing_total: total,
      closing_parts: parts,
      closing_commission_type: cType,
      closing_commission_value: cValue,
      closing_commission_amount: commissionAmount,
      closing_recorded_by: req.user.name,
      closing_recorded_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) { console.error('/api/jobs/:id/closing error:', error.message); return res.status(500).json({ error: 'Server error' }); }
    await logHistory(req.params.id, req.user.id, req.user.name, 'Closing recorded', 'closing', '', `Total $${total} · Parts $${parts} · Commission ${cType === 'percentage' ? cValue + '%' : '$' + cValue} = $${commissionAmount}`);
    // A recorded closing means the job is completed — mark it done (unless it
    // was cancelled, which shouldn't normally have a closing at all).
    let finalJob = job;
    if (job.status !== 'done' && job.status !== 'cancelled') {
      const { data: doneJob } = await supabase.from('jobs').update({ status: 'done', close_date: new Date().toISOString() }).eq('id', req.params.id).select().single();
      if (doneJob) { finalJob = doneJob; await logHistory(req.params.id, req.user.id, req.user.name, 'Status changed', 'status', job.status, 'done'); }
    }
    broadcastNudge('job_change');
    broadcastNudge('jobs_changed');
    res.json(finalJob);
  } catch(e) {
    console.error('/api/jobs/:id/closing error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Job-level receipt token (mirrors the invoice one — receipts no longer require
// an invoice to exist at all).
async function ensureJobReceiptToken(jobId) {
  const { data: job } = await supabase.from('jobs').select('receipt_token').eq('id', jobId).single();
  if (job?.receipt_token) return job.receipt_token;
  const token = crypto.randomBytes(16).toString('hex');
  await supabase.from('jobs').update({ receipt_token: token }).eq('id', jobId);
  return token;
}

// ─── SEND RECEIPT (from the closing) ────────────────────────────────────────────
// Customer receipt policy: the customer receives ONLY the job total and the
// ticket info (job ID, service, address, date). Parts charges are internal and
// NEVER appear on this receipt. When a customer asks for an itemized bill,
// dispatch uses the Customer Invoice section instead (Send Breakdown Receipt).
app.post('/api/jobs/:id/send-receipt', authMiddleware, smsSendLimiter, async (req, res) => {
  try {
    const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.closing_total === null || job.closing_total === undefined) return res.status(400).json({ error: 'Record the closing first — the receipt sends the closing total.' });
    let phone = job.phone || null;
    if (!phone && job.customer_id) {
      const { data: customer } = await supabase.from('customers').select('phone').eq('id', job.customer_id).single();
      phone = customer?.phone || null;
    }
    if (!phone) return res.status(400).json({ error: 'No customer phone on file for this job' });
    const { data: bizSettings } = await supabase.from('settings').select('key,value');
    const st = {}; bizSettings?.forEach(x => st[x.key] = x.value);
    const token = await ensureJobReceiptToken(job.id);
    const link = `${req.protocol}://${req.get('host')}/receipt/${token}`;
    const msg = `Hi! Here's your receipt from ${st.business_name || 'Express Lock&Key'}: ${link}`;
    const finalMsg = await appendComplianceFooterIfFirstContact(phone, msg);
    await twilioClient.messages.create({ body: finalMsg, from: process.env.TWILIO_PHONE_NUMBER, to: phone });
    await logHistory(job.id, req.user.id, req.user.name, 'Receipt sent (closing total)', 'receipt', '', phone);
    res.json({ success: true, link });
  } catch(e) {
    console.error('/api/jobs/:id/send-receipt error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Regenerate a job's masked-call extension — for when the current one has gone
// inactive/stale and the tech needs a fresh working code without re-sending
// the whole ticket. Deactivates the old code first, then allocates a new
// random one via the same pool logic as a first-time assignment.
app.post('/api/jobs/:id/regenerate-extension', authMiddleware, async (req, res) => {
  try {
    const { data: job } = await supabase.from('jobs').select('id').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    await supabase.from('jobs').update({ extension_active: false, call_extension: null }).eq('id', req.params.id);
    const code = await allocateExtension(req.params.id, true);
    if (!code) return res.status(500).json({ error: 'No extensions available' });
    await logHistory(req.params.id, req.user.id, req.user.name, 'Extension regenerated', 'extension', '', 'New ext ' + code);
    res.json({ extension: code });
  } catch(e) {
    console.error('/api/jobs/:id/regenerate-extension error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/techs/:id/commission-preview', authMiddleware, async (req, res) => {
  try {
  const subtotal = parseFloat(req.query.subtotal) || 0;
    const { data: tech } = await supabase.from('users').select('*').eq('id', req.params.id).single();
    if (!tech) return res.status(404).json({ error: 'Tech not found' });
    const resolved = resolveCommission(tech, subtotal);
    res.json({
      type: resolved.type, value: resolved.value,
      amount: calcCommissionAmount(resolved.type, resolved.value, subtotal),
      rule_applied: resolved.rule_applied
    });
  } catch(e) {
    console.error('/api/techs/:id/commission-preview error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/jobs/:id/history', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('ticket_history').select('*').eq('job_id', req.params.id).order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/history error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// General audit log — admin only. Optional entity_type + entity_id filters let
// the frontend pull "everything that happened to this invoice" or "everything
// that happened to this job" without exposing the whole log to non-admins.
app.get('/api/audit-log', authMiddleware, adminOnly, async (req, res) => {
  try {
    let query = supabase.from('audit_log').select('*').order('created_at', { ascending: false }).limit(200);
    if (req.query.entity_type) query = query.eq('entity_type', req.query.entity_type);
    if (req.query.entity_id) query = query.eq('entity_id', req.query.entity_id);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/audit-log error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Admin can freely correct or remove history entries — e.g. fixing a mistaken log
// line. No extra checks beyond admin-only, by design.
app.put('/api/ticket-history/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { action, new_value } = req.body;
    const update = {};
    if (action !== undefined) update.action = action;
    if (new_value !== undefined) update.new_value = new_value;
    const { data, error } = await supabase.from('ticket_history').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/ticket-history/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/ticket-history/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { error } = await supabase.from('ticket_history').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/ticket-history/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── EXTENSION MANAGEMENT (manual, from the ticket UI) ─────────────────────────
app.get('/api/jobs/:id/extension', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('call_extension,extension_active,extension_created_at,extension_last_used_at').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json(job);
  } catch(e) {
    console.error('/api/jobs/:id/extension error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/jobs/:id/extension/renew', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    // Renewing just bumps last_used_at so it survives the inactivity window — keeps the same code.
    if (job.call_extension && job.extension_active) {
      await supabase.from('jobs').update({ extension_last_used_at: new Date().toISOString() }).eq('id', req.params.id);
      return res.json({ extension: job.call_extension, renewed: true });
    }
    const ext = await allocateExtension(req.params.id);
    res.json({ extension: ext, renewed: false, newly_created: true });
  } catch(e) {
    console.error('/api/jobs/:id/extension/renew error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/jobs/:id/extension/free', authMiddleware, adminOnly, async (req, res) => {
  try {
  await supabase.from('jobs').update({ extension_active: false, call_extension: null }).eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/jobs/:id/extension/free error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/extensions/active', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('jobs').select('id,call_extension,tech_name,customer_name,extension_last_used_at,status').eq('extension_active', true).order('call_extension');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/extensions/active error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── TAGS ────────────────────────────────────────────────────────────────────

app.get('/api/tags', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('tags').select('*').order('label');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/tags error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/tags', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { label, color } = req.body;
    if (!label) return res.status(400).json({ error: 'Label required' });
    const { data, error } = await supabase.from('tags').insert({ label, color: color || '#1e6fff' }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/tags error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/tags/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { error } = await supabase.from('tags').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/tags/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/jobs/:id/tags', authMiddleware, async (req, res) => {
  try {
  const { tags } = req.body;
    const { data: old } = await supabase.from('jobs').select('tags').eq('id', req.params.id).single();
    const { data, error } = await supabase.from('jobs').update({ tags, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logHistory(req.params.id, req.user.id, req.user.name, 'Tags updated', 'tags', JSON.stringify(old?.tags), JSON.stringify(tags));
    const newTags = (tags || []).filter(t => !(old?.tags || []).includes(t));
    if (newTags.length) runEventWorkflows('tag_added', data).catch(() => {});
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/tags error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── CALL RECORDINGS ──────────────────────────────────────────────────────────

app.get('/api/jobs/:id/recordings', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('call_recordings').select('*').eq('job_id', req.params.id).order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/recordings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Twilio recording callback
app.post('/api/webhooks/recording', twilioWebhookAuth, async (req, res) => {
  try {
    const { CallSid, RecordingSid, RecordingUrl, RecordingDuration, To, From } = req.body;
    const recordingUrl = RecordingUrl ? RecordingUrl + '.mp3' : null;
    const duration = parseInt(RecordingDuration) || 0;

    // The call-connect step (extension path or customer-callback path) already
    // inserted a row for this exact call, correctly linked to job_id, the
    // instant the call was placed — using call_sid as the shared key. This
    // just fills in the recording itself once it's ready, instead of the old
    // approach of creating a SECOND, disconnected row here via fragile
    // customer/tech NAME matching that had no reliable way to find the right
    // job_id at all — which is why recordings existed in the table but never
    // showed up under the ticket they actually belonged to.
    const { data: updated, error: updErr } = await supabase.from('call_recordings')
      .update({ recording_url: recordingUrl, recording_sid: RecordingSid, duration })
      .eq('call_sid', CallSid).select('id, job_id');
    if (updErr) console.error('Recording webhook: update failed for', CallSid, ':', updErr.message);

    if (!updErr && (!updated || !updated.length)) {
      // No pre-existing row for this call_sid (e.g. the tech-line dial-in path,
      // which doesn't pre-link a job) — fall back to a best-effort insert so
      // the recording isn't lost, even without a confirmed job_id.
      const { data: customer } = await supabase.from('customers').select('name').eq('phone', To).single();
      const { data: tech } = await supabase.from('users').select('name').eq('phone', From).single();
      const { error: fallbackErr } = await supabase.from('call_recordings').insert({
        tech_name: tech?.name || From, customer_name: customer?.name || To,
        call_sid: CallSid, recording_sid: RecordingSid, recording_url: recordingUrl, duration
      });
      if (fallbackErr) console.error('Recording webhook: fallback insert failed for', CallSid, ':', fallbackErr.message);
    }

    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');
  } catch(e) {
    console.error('Recording webhook error:', e.message);
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');
  }
});

// Update masked call to include recording
// ─── INVOICE WITH COMMISSION ──────────────────────────────────────────────────

app.post('/api/invoices/advanced', authMiddleware, async (req, res) => {
  try {
  const { job_id, customer_id, customer_name, tech_id, tech_name, line_items, parts_items, tax_rate, tech_commission_type, tech_commission_value, use_auto_commission } = req.body;
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'invoice_prefix').single();
    const prefix = settings?.value || 'INV';
    const count = await supabase.from('invoices').select('id', { count: 'exact', head: true });
    const num = String((count.count || 0) + 1).padStart(3, '0');
    const id = `${prefix}-${num}`;
    const all_items = [...(line_items || []), ...(parts_items || [])];
    const labor_cost = (line_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const parts_cost = (parts_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const subtotal = labor_cost + parts_cost;
    const tr = parseFloat(tax_rate) || 8.5;
    const tax_amount = subtotal * (tr / 100);
    const total = subtotal + tax_amount;

    let commType = tech_commission_type, commValue = parseFloat(tech_commission_value), ruleApplied = null;
    if (use_auto_commission && tech_id) {
      const { data: tech } = await supabase.from('users').select('*').eq('id', tech_id).single();
      if (tech) {
        const resolved = resolveCommission(tech, subtotal);
        commType = resolved.type; commValue = resolved.value; ruleApplied = resolved.rule_applied;
      }
    }
    const tech_commission_amount = calcCommissionAmount(commType, commValue, subtotal);

    const { data, error } = await supabase.from('invoices').insert({
      id, job_id, customer_id, customer_name, tech_id, tech_name,
      line_items: all_items, subtotal, tax_rate: tr, tax_amount, total, status: 'unpaid',
      parts_cost, labor_cost, tech_commission_type: commType, tech_commission_value: commValue,
      tech_commission_amount, commission_rule_applied: ruleApplied
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (job_id) {
      await supabase.from('jobs').update({ invoice_id: id, status: 'done', close_date: new Date().toISOString() }).eq('id', job_id);
      await logHistory(job_id, req.user.id, req.user.name, 'Invoice created', 'invoice_id', '', id);
    }
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/advanced error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Send receipt
app.post('/api/invoices/:id/receipt', authMiddleware, async (req, res) => {
  try {
    const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    const { data: customer } = await supabase.from('customers').select('phone').eq('id', inv.customer_id).single();
    const { data: bizSettings } = await supabase.from('settings').select('key,value');
    const s = {}; bizSettings?.forEach(x => s[x.key] = x.value);
    const token = await ensureReceiptToken(inv.id);
    const link = `${req.protocol}://${req.get('host')}/receipt/${token}`;
    const msg = `Hi! Here's your receipt from ${s.business_name || 'Express Lock&Key'}: ${link}`;
    if (customer?.phone) {
      const finalMsg = await appendComplianceFooterIfFirstContact(customer.phone, msg);
      await twilioClient.messages.create({ body: finalMsg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
      await supabase.from('invoices').update({ receipt_sent: true }).eq('id', req.params.id);
      if (inv.job_id) await logHistory(inv.job_id, req.user.id, req.user.name, 'Receipt sent', 'receipt', '', customer.phone);
      res.json({ success: true, link });
    } else { res.status(400).json({ error: 'No phone on file' }); }
  } catch(e) {
    console.error('/api/invoices/:id/receipt error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Serve frontend
// ─── RESERVE WITH GOOGLE BOOKINGS ──────────────────────────────────────────────
// NOT YET CONNECTED to Google's real Reservations integration — that requires
// Partner Portal approval and Google's exact CreateBooking/CheckAvailability
// protocol (gRPC or REST, with mutual TLS + HTTP Basic Auth credentials Google
// issues after approval). This endpoint is a structural placeholder shaped like
// Google's real booking payload, so once approved, only the auth layer and field
// mapping need to change — not the underlying CRM plumbing.
app.post('/api/google-reserve/booking', async (req, res) => {
  try {
    const { data: setting } = await supabase.from('settings').select('value').eq('key', 'google_reserve_connected').single();
    if (setting?.value !== 'true') return res.status(503).json({ error: 'Reserve with Google is not connected yet. Configure it in Settings once Google partner credentials are issued.' });

    const { google_booking_id, customer_name, customer_phone, customer_email, service_name, start_time, end_time } = req.body;
    if (!google_booking_id) return res.status(400).json({ error: 'google_booking_id required (idempotency key)' });

    // Idempotent — Google may retry this call, so re-sending the same booking ID
    // should not create duplicates.
    const { data: existing } = await supabase.from('google_bookings').select('*').eq('google_booking_id', google_booking_id).single();
    if (existing) return res.json(existing);

    const { data, error } = await supabase.from('google_bookings').insert({
      google_booking_id, customer_name, customer_phone, customer_email, service_name,
      start_time, end_time, status: 'pending', raw_payload: req.body
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await createNotification('new_booking', 'New Google Reserve Appointment', `${customer_name || 'Customer'} — ${service_name || 'Service'}`);
    res.json(data);
  } catch(e) {
    console.error('Google Reserve booking webhook error:', e.message);
    res.status(500).json({ error: 'Internal error processing booking' });
  }
});

app.get('/api/google-reserve/bookings', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('google_bookings').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/google-reserve/bookings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Converts a received Google booking into a real CRM job — same pattern as the
// old manual booking-confirm flow, just sourced from Google instead.
app.put('/api/google-reserve/bookings/:id/confirm', authMiddleware, async (req, res) => {
  try {
  const { tech_id, tech_name } = req.body;
    const { data: booking } = await supabase.from('google_bookings').select('*').eq('id', req.params.id).single();
    if (!booking) return res.status(404).json({ error: 'Booking not found' });

    let customer = await supabase.from('customers').select('*').eq('phone', booking.customer_phone).single();
    let customerRow = customer.data;
    if (!customerRow && booking.customer_phone) {
      const created = await supabase.from('customers').insert({ name: booking.customer_name, phone: booking.customer_phone, email: booking.customer_email }).select().single();
      customerRow = created.data;
    }
    const jobId = await generateJobId();
    await supabase.from('jobs').insert({
      id: jobId, title: booking.service_name || 'Reserve with Google Appointment', customer_id: customerRow?.id,
      customer_name: booking.customer_name, phone: booking.customer_phone, tech_id: tech_id || null, tech_name: tech_name || null,
      status: tech_id ? 'assigned' : 'new', priority: 'med', job_date: todayInBusinessTz(), scheduled_date: booking.start_time,
      source: 'Reserve with Google'
    });
    await supabase.from('google_bookings').update({ status: 'confirmed', job_id: jobId }).eq('id', req.params.id);
    runEventWorkflows('new_booking', { id: jobId, customer_name: booking.customer_name, job_type: booking.service_name }).catch(() => {});
    res.json({ success: true, job_id: jobId });
  } catch(e) {
    console.error('/api/google-reserve/bookings/:id/confirm error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/google-reserve/bookings/:id/cancel', authMiddleware, async (req, res) => {
  try {
  await supabase.from('google_bookings').update({ status: 'cancelled' }).eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/google-reserve/bookings/:id/cancel error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/receipt/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'receipt.html')));
app.get('/sms-optin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sms-optin.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));

// Public — no auth. Token is unguessable (random), this is the only key protecting it.
app.get('/api/receipt/:token', async (req, res) => {
  try {
    const { data: s } = await supabase.from('settings').select('key,value');
    const settings = {}; s?.forEach(x => settings[x.key] = x.value);
    const biz = {
      business_name: settings.business_name || 'Express Lock&Key',
      business_phone: settings.business_phone || '',
      business_email: settings.business_email || '',
      review_link: settings.review_link || ''
    };

    // 1) JOB (closing) receipt — total + ticket info ONLY. Parts charges are
    //    internal and never leave the system on this receipt.
    const { data: job } = await supabase.from('jobs').select('id,customer_name,title,job_type,address,job_date,closing_total').eq('receipt_token', req.params.token).single();
    if (job && job.closing_total !== null && job.closing_total !== undefined) {
      return res.json({
        receipt_type: 'closing',
        invoice_id: job.id, // rendered as "Receipt JOB-xxxx" — the ticket reference
        customer_name: job.customer_name,
        service: job.title || job.job_type || null,
        address: job.address || null,
        total: job.closing_total,
        invoice_date: job.job_date,
        status: 'paid',
        breakdown: null, // NEVER a breakdown here — that's the invoice receipt's job
        ...biz
      });
    }

    // 2) INVOICE (breakdown) receipt — the customer-facing itemization tool.
    const { data: inv } = await supabase.from('invoices').select('*').eq('receipt_token', req.params.token).single();
    if (!inv) return res.status(404).json({ error: 'Receipt not found' });
    let ticket = null;
    if (inv.job_id) {
      const { data: j } = await supabase.from('jobs').select('title,job_type,address').eq('id', inv.job_id).single();
      ticket = j || null;
    }
    // Never expose internal cost breakdown — only total + optional manual breakdown the admin chose to show.
    res.json({
      receipt_type: 'breakdown',
      invoice_id: inv.id,
      customer_name: inv.customer_name,
      service: ticket ? (ticket.title || ticket.job_type || null) : null,
      address: ticket ? (ticket.address || null) : null,
      total: inv.total,
      invoice_date: inv.invoice_date,
      status: inv.status,
      breakdown: inv.receipt_breakdown || null, // [{label, amount}] manually set by admin, or null = total only
      ...biz
    });
  } catch(e) {
    console.error('/api/receipt/:token error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// NOTE: The SPA catch-all route (app.get('*')), the Express error handler, and
// app.listen() are registered at the VERY BOTTOM of this file. They MUST come
// after every route registration: Express matches routes in registration order,
// and a mid-file catch-all silently swallows every GET route registered below
// it, serving index.html instead of JSON. That exact bug kept
// /api/analytics/dashboard, /api/analytics/yearly-trend, /api/jobs/daily-board,
// /api/workflows, /api/ai-chat, /api/status-labels and /api/admin-report/log
// dead in production. Never register a catch-all anywhere but the end.

// ─── BOOKINGS ─────────────────────────────────────────────────────────────────

// ─── LIVE EVENT-TRIGGERED WORKFLOWS ─────────────────────────────────────────────
// Runs whenever a real event happens (new_job, job_assigned, status_change),
// checking each active workflow's trigger_condition against the job. Conditions
// support tags and status, not just arbitrary fields, since those are the two
// most useful checks dispatchers actually use day to day.
async function runEventWorkflows(triggerEvent, jobData) {
  try {
    const { data: workflows } = await supabase.from('workflows').select('*').eq('trigger_type', 'event').eq('trigger_event', triggerEvent).eq('active', true);
    for (const wf of (workflows || [])) {
      if (!workflowConditionMatches(wf.trigger_condition, jobData)) continue;
      const { data: tech } = jobData.tech_id ? await supabase.from('users').select('phone').eq('id', jobData.tech_id).single() : { data: null };
      const actionData = { ...jobData, tech_phone: tech?.phone || null };
      await executeWorkflowActions(wf.actions, actionData);
      await supabase.from('workflows').update({ run_count: (wf.run_count || 0) + 1, last_run: new Date().toISOString() }).eq('id', wf.id);
    }
  } catch(e) { console.log('Event workflow error:', e.message); }
}

// Evaluates a workflow's trigger_condition against a job. Supports:
//   { field: 'tags', operator: 'contains', value: 'VIP' }       — tag-based
//   { field: 'status', operator: 'equals', value: 'in-progress' } — status-based
//   { field: <any job column>, operator: 'equals'|'contains', value: ... } — generic
// No condition set (empty {}) always matches.
function workflowConditionMatches(condition, jobData) {
  if (!condition || !condition.field || condition.value === undefined || condition.value === '') return true;
  const fieldVal = jobData[condition.field];
  if (condition.field === 'tags') {
    const tags = jobData.tags || [];
    return tags.includes(condition.value);
  }
  if (condition.operator === 'equals') return fieldVal === condition.value;
  if (condition.operator === 'contains') return String(fieldVal || '').toLowerCase().includes(String(condition.value).toLowerCase());
  return true;
}


// ─── WORKFLOWS (Zapier-style) ─────────────────────────────────────────────────

app.get('/api/workflows', authMiddleware, requirePerm('perm_view_workflows'), async (req, res) => {
  try {
  const { data, error } = await supabase.from('workflows').select('*').order('created_at');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/workflows error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/workflows', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('workflows').insert(req.body).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/workflows error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/workflows/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('workflows').update(req.body).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/workflows/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/workflows/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  await supabase.from('workflows').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/workflows/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/workflows/:id/test', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data: wf } = await supabase.from('workflows').select('*').eq('id', req.params.id).single();
    if (!wf) return res.status(404).json({ error: 'Not found' });
    const testData = { customer_name: 'Test Customer', job_id: 'JOB-001', job_type: 'Car Lockout', address: '123 Test St', tech_name: 'Test Tech', phone: req.body.test_phone || '', revenue: '0', total_jobs: '1', pending: '0' };
    const result = await executeWorkflowActions(wf.actions, testData);
    await supabase.from('workflows').update({ run_count: (wf.run_count||0)+1, last_run: new Date().toISOString() }).eq('id', req.params.id);
    res.json({ success: true, result });
  } catch(e) {
    console.error('/api/workflows/:id/test error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

async function executeWorkflowActions(actions, data) {
  const results = [];
  const { data: s } = await supabase.from('settings').select('key,value');
  const settings = {}; s?.forEach(x => settings[x.key] = x.value);
  for (const action of (actions || [])) {
    try {
      const msg = (action.message || '').replace(/{(\w+)}/g, (_, k) => data[k] || '');
      const toPhone = action.to === 'customer' ? data.phone : action.to === 'tech' ? data.tech_phone : action.phone;
      if (action.type === 'send_sms' && toPhone) {
        await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: toPhone });
        results.push({ action: 'send_sms', to: toPhone, status: 'sent' });
      } else if (action.type === 'send_whatsapp' && toPhone) {
        const waFrom = settings.whatsapp_from || 'whatsapp:+14155238886';
        const waTo = toPhone.startsWith('whatsapp:') ? toPhone : `whatsapp:${toPhone}`;
        await twilioClient.messages.create({ body: msg, from: waFrom, to: waTo });
        results.push({ action: 'send_whatsapp', to: toPhone, status: 'sent' });
      } else if (action.type === 'create_notification') {
        await createNotification('workflow', action.title || 'Workflow', msg);
        results.push({ action: 'notification', status: 'created' });
      } else if (action.type === 'update_status' && data.id) {
        await supabase.from('jobs').update({ status: action.status }).eq('id', data.id);
        results.push({ action: 'update_status', status: action.status });
      } else if (action.type === 'assign_tag' && data.id) {
        const { data: j } = await supabase.from('jobs').select('tags').eq('id', data.id).single();
        const tags = [...(j?.tags || [])]; if (!tags.includes(action.tag)) tags.push(action.tag);
        await supabase.from('jobs').update({ tags }).eq('id', data.id);
        results.push({ action: 'assign_tag', tag: action.tag });
      } else if (action.type === 'webhook_post' && action.url) {
        const r = await fetch(action.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...data, message: msg }) });
        results.push({ action: 'webhook', url: action.url, status: r.status });
      } else if (action.type === 'send_report') {
        const report = await generateDailyReport();
        const reportMsg = msg.replace('{total_jobs}', report.total).replace('{pending}', report.pending).replace('{revenue}', report.revenue);
        if (settings.admin_phone) {
          await twilioClient.messages.create({ body: reportMsg, from: process.env.TWILIO_PHONE_NUMBER, to: settings.admin_phone });
        }
        results.push({ action: 'send_report', status: 'sent' });
      }
    } catch(e) { results.push({ action: action.type, status: 'error', error: e.message }); }
  }
  return results;
}

async function generateDailyReport() {
  const today = todayInBusinessTz();
  const { data: jobs } = await supabase.from('jobs').select('*').eq('job_date', today);
  const { data: invoices } = await supabase.from('invoices').select('*').eq('invoice_date', today).eq('status', 'paid');
  const revenue = invoices?.reduce((a, i) => a + (i.total || 0), 0) || 0;
  return { total: jobs?.length || 0, pending: jobs?.filter(j => j.status === 'new').length || 0, revenue: revenue.toFixed(2) };
}

// Scheduled workflow runner (call this endpoint via cron or external scheduler)
app.post('/api/admin-report/test', authMiddleware, adminOnly, async (req, res) => {
  try {
  await sendAdminReport('manual', '✅ FieldPro test message — if you see this, your admin reporting channel is working.');
    const { data: log } = await supabase.from('admin_report_log').select('*').order('created_at', { ascending: false }).limit(3);
    res.json({ success: true, attempts: log || [] });
  } catch(e) {
    console.error('/api/admin-report/test error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin-report/log', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('admin_report_log').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/admin-report/log error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Runs every due scheduled workflow. Called by the built-in interval below (so
// scheduled workflows work with ZERO external setup) and by the manual/external
// endpoint for on-demand triggering.
async function runScheduledWorkflows() {
  const now = new Date();
  const { data: workflows } = await supabase.from('workflows').select('*').eq('trigger_type', 'schedule').eq('active', true);
  let ran = 0;
  for (const wf of (workflows || [])) {
    const shouldRun = checkSchedule(wf.trigger_schedule, now, wf.last_run);
    if (shouldRun) {
      await executeWorkflowActions(wf.actions, {});
      await supabase.from('workflows').update({ run_count: (wf.run_count || 0) + 1, last_run: now.toISOString() }).eq('id', wf.id);
      ran++;
    }
  }
  return ran;
}

// Built-in scheduler: checks for due workflows every minute. Previously this
// ONLY ran if an external cron hit /api/workflows/run-scheduled — which nothing
// was configured to do — so scheduled workflows silently never fired.
setInterval(() => { runScheduledWorkflows().catch(e => console.error('Scheduled workflow tick error:', e.message)); }, 60 * 1000);

app.post('/api/workflows/run-scheduled', async (req, res) => {
  try {
    // Same rule as /api/alerts/run-checks: requires CRON_SECRET (never JWT_SECRET —
    // that's the token-signing key and should never double as a shared API secret),
    // and a missing env var means locked, not open. Note: this endpoint is now
    // OPTIONAL — the built-in interval above runs scheduled workflows on its own.
    const secret = req.headers['x-cron-secret'];
    if (!process.env.CRON_SECRET || secret !== process.env.CRON_SECRET) return res.status(401).json({ error: 'Unauthorized' });
    const ran = await runScheduledWorkflows();
    res.json({ success: true, ran });
  } catch(e) {
    console.error('/api/workflows/run-scheduled error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

function checkSchedule(schedule, now, lastRun) {
  if (!schedule) return false;
  const last = lastRun ? new Date(lastRun) : new Date(0);
  const hoursSinceLast = (now - last) / (1000 * 60 * 60);
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: BUSINESS_TZ, weekday: 'short', hour: 'numeric', hour12: false }).formatToParts(now);
  const map = {}; parts.forEach(p => map[p.type] = p.value);
  const hourEastern = parseInt(map.hour) % 24;
  const dayEastern = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].indexOf(map.weekday);
  if (schedule === 'hourly') return hoursSinceLast >= 1;
  if (schedule === 'daily_8am') return hourEastern === 8 && hoursSinceLast >= 23;
  if (schedule === 'daily_6pm') return hourEastern === 18 && hoursSinceLast >= 23;
  if (schedule === 'weekly_monday') return dayEastern === 1 && hoursSinceLast >= 167;
  return false;
}

// ─── AI ASSISTANT ─────────────────────────────────────────────────────────────

app.get('/api/ai-chat', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('ai_chat').select('*').eq('user_id', req.user.id).order('created_at').limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/ai-chat error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/ai-chat/clear', authMiddleware, async (req, res) => {
  try {
  await supabase.from('ai_chat').delete().eq('user_id', req.user.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/ai-chat/clear error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/ai-assistant', authMiddleware, aiLimiter, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  try {
    // Gather CRM context
    const [{ data: jobs }, { data: customers }, { data: techs }, { data: invoices }, { data: history }] = await Promise.all([
      supabase.from('jobs').select('*').order('created_at', { ascending: false }).limit(50),
      supabase.from('customers').select('*').limit(30),
      supabase.from('users').select('id,name,role,status,color,initials').eq('role', 'tech'),
      supabase.from('invoices').select('*').order('created_at', { ascending: false }).limit(30),
      supabase.from('ai_chat').select('*').eq('user_id', req.user.id).order('created_at').limit(10)
    ]);

    const today = todayInBusinessTz();
    const revenue = invoices?.filter(i => i.status === 'paid').reduce((a, i) => a + (i.total || 0), 0) || 0;
    const outstanding = invoices?.filter(i => i.status === 'unpaid').reduce((a, i) => a + (i.total || 0), 0) || 0;

    const systemPrompt = `You are the AI assistant for Express Lock&Key CRM. You have full access to the business data and can execute tasks directly.

CURRENT CRM DATA:
- Total Jobs: ${jobs?.length || 0}
- New/Pending: ${jobs?.filter(j => j.status === 'new').length || 0}
- In Progress: ${jobs?.filter(j => j.status === 'in-progress').length || 0}
- Done Today: ${jobs?.filter(j => j.job_date === today && j.status === 'done').length || 0}
- Technicians: ${techs?.map(t => t.name + ' (' + t.status + ')').join(', ')}
- Revenue Collected: $${revenue.toFixed(2)}
- Outstanding: $${outstanding.toFixed(2)}
- Recent Jobs: ${jobs?.slice(0, 10).map(j => j.id + ' ' + j.title + ' ' + j.customer_name + ' [' + j.status + ']').join('; ')}

WHAT YOU CAN DO:
1. Answer questions about jobs, revenue, techs, customers
2. Give instructions for actions prefixed with [ACTION]:
   - [ACTION:assign_tech] job_id=JOB-001 tech_name=Marcus R.
   - [ACTION:update_status] job_id=JOB-001 status=done
   - [ACTION:send_sms] phone=+13055550101 message=Your text here
   - [ACTION:create_job] title=Car Lockout customer=John phone=+1305... address=123 Main St
   - [ACTION:send_report] type=daily
   - [ACTION:add_tag] job_id=JOB-001 tag=VIP

Be concise, direct, and professional. When executing actions, confirm what you did. If asked to do multiple things, list each action clearly.`;

    const messages = [
      ...(history || []).map(h => ({ role: h.role, content: h.content })),
      { role: 'user', content: message }
    ];

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY || '', 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1024, system: systemPrompt, messages })
    });
    const aiData = await aiRes.json();
    const reply = aiData.content?.[0]?.text || 'Sorry, I could not process that.';

    // Parse and execute any actions in the reply
    const actionsTaken = [];
    const actionRegex = /\[ACTION:(\w+)\]\s*([^\n]*)/g;
    let match;
    while ((match = actionRegex.exec(reply)) !== null) {
      const actionType = match[1];
      const params = {};
      // Params are space-separated key=value pairs, but values themselves (addresses,
      // SMS text, names) can contain spaces — so split only on spaces that precede
      // the next "word=" pattern, not every space in the line.
      const paramStr = match[2];
      const paramRegex = /(\w+)=((?:(?!\s+\w+=).)*)/g;
      let pMatch;
      while ((pMatch = paramRegex.exec(paramStr)) !== null) {
        params[pMatch[1]] = pMatch[2].trim();
      }
      try {
        if (actionType === 'assign_tech' && params.job_id && params.tech_name) {
          const tech = techs?.find(t => t.name.toLowerCase().includes(params.tech_name.toLowerCase()));
          if (tech) { await supabase.from('jobs').update({ tech_id: tech.id, tech_name: tech.name, status: 'assigned' }).eq('id', params.job_id); actionsTaken.push('Assigned ' + tech.name + ' to ' + params.job_id); }
        } else if (actionType === 'update_status' && params.job_id) {
          await supabase.from('jobs').update({ status: params.status }).eq('id', params.job_id); actionsTaken.push('Updated ' + params.job_id + ' to ' + params.status);
        } else if (actionType === 'send_sms' && params.phone) {
          await twilioClient.messages.create({ body: params.message || '', from: process.env.TWILIO_PHONE_NUMBER, to: params.phone }); actionsTaken.push('SMS sent to ' + params.phone);
        } else if (actionType === 'add_tag' && params.job_id) {
          const { data: j } = await supabase.from('jobs').select('tags').eq('id', params.job_id).single();
          const tags = [...(j?.tags || [])]; if (!tags.includes(params.tag)) tags.push(params.tag);
          await supabase.from('jobs').update({ tags }).eq('id', params.job_id); actionsTaken.push('Added tag ' + params.tag + ' to ' + params.job_id);
        } else if (actionType === 'send_report') {
          const report = await generateDailyReport(); actionsTaken.push('Report generated: ' + JSON.stringify(report));
        } else if (actionType === 'create_job' && params.title && params.customer && params.phone) {
          let customer = await supabase.from('customers').select('*').eq('phone', params.phone).single();
          let customerRow = customer.data;
          if (!customerRow) {
            const created = await supabase.from('customers').insert({ name: params.customer, phone: params.phone, address: params.address || null }).select().single();
            customerRow = created.data;
          }
          const newJobId = await generateJobId();
          await supabase.from('jobs').insert({
            id: newJobId, title: params.title, customer_id: customerRow?.id, customer_name: params.customer,
            phone: params.phone, address: params.address || null, status: 'new', priority: 'med', job_date: todayInBusinessTz()
          });
          actionsTaken.push('Created job ' + newJobId + ' for ' + params.customer);
        }
      } catch(e) { actionsTaken.push('Action failed: ' + e.message); }
    }

    // Save to chat history
    await supabase.from('ai_chat').insert([
      { user_id: req.user.id, role: 'user', content: message },
      { user_id: req.user.id, role: 'assistant', content: reply, actions_taken: actionsTaken }
    ]);

    res.json({ reply, actions_taken: actionsTaken });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ─── EDITABLE INVOICES ────────────────────────────────────────────────────────

app.put('/api/invoices/:id/edit', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { line_items, parts_items, tax_rate, tech_commission_type, tech_commission_value, notes } = req.body;
    const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    // Save edit history
    const editHistory = [...(inv.edit_history || []), { edited_by: req.user.name, edited_at: new Date().toISOString(), previous: { line_items: inv.line_items, subtotal: inv.subtotal, total: inv.total } }];
    const all_items = [...(line_items || []), ...(parts_items || [])];
    const labor_cost = (line_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const parts_cost = (parts_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const subtotal = labor_cost + parts_cost;
    const tr = parseFloat(tax_rate) || inv.tax_rate || 8.5;
    const tax_amount = subtotal * (tr / 100);
    const total = subtotal + tax_amount;
    let tech_commission_amount = 0;
    const commType = tech_commission_type || inv.tech_commission_type || 'percentage';
    const commVal = parseFloat(tech_commission_value) || inv.tech_commission_value || 0;
    if (commType === 'percentage') tech_commission_amount = subtotal * (commVal / 100);
    else tech_commission_amount = commVal;
    const { data, error } = await supabase.from('invoices').update({
      line_items: all_items, labor_cost, parts_cost, subtotal, tax_rate: tr, tax_amount, total,
      tech_commission_type: commType, tech_commission_value: commVal, tech_commission_amount, notes,
      edit_history: editHistory, last_edited_by_user_id: req.user.id, last_edited_by_name: req.user.name, last_edited_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('invoice', req.params.id, req.user.id, req.user.name, 'edited', `Edited invoice — new total $${total.toFixed(2)}`);
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/:id/edit error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Manual receipt breakdown — only affects what the customer sees on the public receipt page.
// Internal invoice (commission, real costs) stays untouched. Pass breakdown: null to clear it
// and just show the total again.
app.put('/api/invoices/:id/receipt-breakdown', authMiddleware, async (req, res) => {
  try {
  const { breakdown } = req.body; // [{label, amount}] or null
    const { data, error } = await supabase.from('invoices').update({ receipt_breakdown: breakdown }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/:id/receipt-breakdown error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Reopen a closed job
app.put('/api/jobs/:id/reopen', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { reason } = req.body;
    const { data, error } = await supabase.from('jobs').update({ status: 'in-progress', reopened_at: new Date().toISOString(), reopen_reason: reason || 'Reopened by admin', close_date: null }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logHistory(req.params.id, req.user.id, req.user.name, 'Job reopened', 'status', 'done', 'in-progress');
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/reopen error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});


// ─── CUSTOM STATUS LABELS ─────────────────────────────────────────────────────
app.get('/api/status-labels', authMiddleware, async (req, res) => {
  try {
  const { data } = await supabase.from('settings').select('value').eq('key', 'custom_status_labels').single();
    const labels = data?.value ? JSON.parse(data.value) : ['new','assigned','in-progress','done','cancelled'];
    res.json(labels);
  } catch(e) {
    console.error('/api/status-labels error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/status-labels', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { labels } = req.body;
    if (!Array.isArray(labels) || !labels.length) return res.status(400).json({ error: 'labels must be a non-empty array' });
    // Same fix as /api/settings: check the upsert's error instead of assuming
    // success. This was the exact bug behind "status labels reset to defaults
    // every time I update the index" — the save silently no-op'd on failure.
    const { error } = await supabase.from('settings').upsert({ key: 'custom_status_labels', value: JSON.stringify(labels) });
    if (error) { console.error('/api/status-labels upsert failed:', error.message); return res.status(500).json({ error: 'Failed to save status labels — check Supabase permissions/RLS on the settings table' }); }
    res.json({ success: true, labels });
  } catch(e) {
    console.error('/api/status-labels error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── DASHBOARD ANALYTICS ──────────────────────────────────────────────────────
app.get('/api/analytics/dashboard', authMiddleware, adminOnly, async (req, res) => {
  try {
  const now = new Date();
    const today = todayInBusinessTz();
    const nowEastern = nowInBusinessTz();
    const weekStart = new Date(nowEastern); weekStart.setDate(nowEastern.getDate() - nowEastern.getDay());
    const monthStart = new Date(nowEastern.getFullYear(), nowEastern.getMonth(), 1);
    const isAdmin = req.user.role === 'admin';
    let canSeeRevenue = isAdmin;
    if (!isAdmin) {
      const { data: u } = await supabase.from('users').select('perm_view_total_revenue').eq('id', req.user.id).single();
      canSeeRevenue = u?.perm_view_total_revenue === true;
    }

    const [jobsAll, invoicesAll, { data: techs }] = await Promise.all([
      fetchAllRows(() => supabase.from('jobs').select('*').order('created_at', { ascending: false })),
      fetchAllRows(() => supabase.from('invoices').select('*')), // per-job invoice data is fine for dispatchers — they handle individual job finance
      supabase.from('users').select('id,name,color,initials,role').eq('role', 'tech')
    ]);

    // ── DASHBOARD FILTERS ──
    // ?from=YYYY-MM-DD&to=YYYY-MM-DD → restrict analysis window (job_date / invoice_date)
    // ?tech=<uuid> or ?tech=former:<name> → restrict to one tech (incl. former techs)
    const { from: fFrom, to: fTo, tech: fTech } = req.query;
    const inWin = (ds) => {
      if (!fFrom && !fTo) return true;
      if (!ds) return false;
      ds = String(ds).slice(0, 10);
      if (fFrom && ds < fFrom) return false;
      if (fTo && ds > fTo) return false;
      return true;
    };
    let jobs = (jobsAll || []).filter(j => inWin(j.job_date || (j.created_at || '').slice(0, 10)));
    let invoices = (invoicesAll || []).filter(i => inWin(i.invoice_date || (i.created_at || '').slice(0, 10)));
    if (fTech) {
      if (fTech.startsWith('former:')) {
        const fname = fTech.slice(7);
        jobs = jobs.filter(j => !j.tech_id && j.tech_name === fname);
        invoices = invoices.filter(i => !i.tech_id && i.tech_name === fname);
      } else {
        jobs = jobs.filter(j => j.tech_id === fTech);
        invoices = invoices.filter(i => i.tech_id === fTech);
      }
    }

    const todayJobs = jobs?.filter(j => j.job_date === today) || [];
    const weekJobs = jobs?.filter(j => new Date(j.job_date) >= weekStart) || [];
    const monthJobs = jobs?.filter(j => new Date(j.job_date) >= monthStart) || [];

    // Jobs by status
    const statusCounts = {};
    (jobs || []).forEach(j => { statusCounts[j.status] = (statusCounts[j.status] || 0) + 1; });

    // Jobs by type
    const typeCounts = {};
    (jobs || []).forEach(j => { if(j.job_type) typeCounts[j.job_type] = (typeCounts[j.job_type] || 0) + 1; });

    // Tech performance — per-tech revenue is visible to dispatchers (it's per-job, not company total),
    // only the aggregate company-wide revenue object below is gated by canSeeRevenue.
    // Closing-first revenue: a job's closing_total is the record; paid invoices
    // only count for legacy jobs that have no closing.
    const rev = jobRevenueResolver(jobs, invoices);
    const techPerf = (techs || []).map(t => {
      const tJobs = jobs?.filter(j => j.tech_id === t.id) || [];
      return {
        tech: t,
        total: tJobs.length,
        done: tJobs.filter(j => j.status === 'done').length,
        cancelled: tJobs.filter(j => j.status === 'cancelled').length,
        inProgress: tJobs.filter(j => j.status === 'in-progress').length,
        revenue: tJobs.reduce((a, j) => a + rev.forJob(j.id), 0),
        completionRate: tJobs.length ? Math.round(tJobs.filter(j => j.status === 'done').length / tJobs.length * 100) : 0
      };
    });

    // Former techs intentionally EXCLUDED from the Tech Performance widget per
    // Hassan's request — the widget shows the current roster only. Former
    // techs still count in overall trends, the 12-month chart, and its tech
    // filter checklist; their jobs are never dropped from aggregate analysis.
    techPerf.sort((a, b) => b.total - a.total);

    // Last 7 days job trend
    const last7 = [];
    for(let i=6; i>=0; i--) {
      const d = new Date(nowEastern); d.setDate(nowEastern.getDate() - i);
      const ds = dateInBusinessTz(d);
      const dayJobs = jobs?.filter(j => j.job_date === ds) || [];
      last7.push({ date: ds, label: d.toLocaleDateString('en-US',{weekday:'short'}), total: dayJobs.length, done: dayJobs.filter(j=>j.status==='done').length, cancelled: dayJobs.filter(j=>j.status==='cancelled').length });
    }

    // Company-wide revenue totals — confidential, gated by canSeeRevenue
    // Closings count on the job's date; paid invoices only for jobs without a
    // closing (legacy). Outstanding stays invoice-based — a closing is money
    // already collected by the tech, never "owed".
    const jobsWithClosing = (jobs || []).filter(j => j.closing_total !== null && j.closing_total !== undefined);
    const closingSum = (pred) => jobsWithClosing.filter(pred).reduce((a, j) => a + (parseFloat(j.closing_total) || 0), 0);
    const legacyInvSum = (pred) => (invoices || []).filter(i => i.status === 'paid' && !rev.hasClosing(i.job_id) && pred(i)).reduce((a, i) => a + (i.total || 0), 0);
    const revenueData = canSeeRevenue ? {
      today: closingSum(j => j.job_date === today) + legacyInvSum(i => i.invoice_date === today),
      week: closingSum(j => new Date(j.job_date) >= weekStart) + legacyInvSum(i => new Date(i.invoice_date) >= weekStart),
      month: closingSum(j => new Date(j.job_date) >= monthStart) + legacyInvSum(i => new Date(i.invoice_date) >= monthStart),
      outstanding: invoices?.filter(i=>i.status==='unpaid' && !rev.hasClosing(i.job_id)).reduce((a,i)=>a+(i.total||0),0) || 0
    } : null;

    // ── EXPANDED ANALYTICS ──────────────────────────────────────────────────────
    const lastWeekStart = new Date(weekStart); lastWeekStart.setDate(lastWeekStart.getDate() - 7);
    const lastWeekEnd = new Date(weekStart); lastWeekEnd.setMilliseconds(-1);
    const lastWeekJobs = jobs?.filter(j => new Date(j.job_date) >= lastWeekStart && new Date(j.job_date) <= lastWeekEnd) || [];
    const lastMonthStart = new Date(nowEastern.getFullYear(), nowEastern.getMonth() - 1, 1);
    const lastMonthEnd = new Date(monthStart); lastMonthEnd.setMilliseconds(-1);
    const lastMonthJobs = jobs?.filter(j => new Date(j.job_date) >= lastMonthStart && new Date(j.job_date) <= lastMonthEnd) || [];

    // Week-over-week / month-over-month growth — jobs count and revenue, with % change.
    // null revenue values mean "hidden, not zero" so the frontend doesn't show a misleading 0%.
    function pctChange(curr, prev) { if (!prev) return curr > 0 ? 100 : 0; return Math.round(((curr - prev) / prev) * 100); }
    const weekRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= weekStart && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const lastWeekRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= lastWeekStart && new Date(i.invoice_date) <= lastWeekEnd && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const monthRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= monthStart && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const lastMonthRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= lastMonthStart && new Date(i.invoice_date) <= lastMonthEnd && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const growth = {
      jobs_wow: pctChange(weekJobs.length, lastWeekJobs.length),
      jobs_mom: pctChange(monthJobs.length, lastMonthJobs.length),
      revenue_wow: canSeeRevenue ? pctChange(weekRevenue, lastWeekRevenue) : null,
      revenue_mom: canSeeRevenue ? pctChange(monthRevenue, lastMonthRevenue) : null
    };

    // Average job value trend over the last 8 weeks — shows whether typical job size is rising or falling.
    const avgJobValueTrend = [];
    if (canSeeRevenue) {
      for (let w = 7; w >= 0; w--) {
        const wStart = new Date(weekStart); wStart.setDate(wStart.getDate() - w * 7);
        const wEnd = new Date(wStart); wEnd.setDate(wEnd.getDate() + 6);
        const wInvoices = invoices?.filter(i => new Date(i.invoice_date) >= wStart && new Date(i.invoice_date) <= wEnd && i.status === 'paid') || [];
        const avg = wInvoices.length ? wInvoices.reduce((a,i) => a+(i.total||0), 0) / wInvoices.length : 0;
        avgJobValueTrend.push({ label: wStart.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), avg: Math.round(avg * 100) / 100, count: wInvoices.length });
      }
    }

    // Average tech response time (assignment -> confirmation), in minutes, over confirmed jobs.
    const confirmedJobs = (jobs || []).filter(j => j.confirmed_by_tech && j.assigned_at && j.confirmed_at);
    const avgResponseMinutes = confirmedJobs.length
      ? Math.round(confirmedJobs.reduce((a, j) => a + (new Date(j.confirmed_at) - new Date(j.assigned_at)) / 60000, 0) / confirmedJobs.length)
      : null;

    // Repeat-customer rate — % of customers with more than one job, all time.
    const customerJobCounts = {};
    (jobs || []).forEach(j => { if (j.customer_id) customerJobCounts[j.customer_id] = (customerJobCounts[j.customer_id] || 0) + 1; });
    const totalCustomersWithJobs = Object.keys(customerJobCounts).length;
    const repeatCustomers = Object.values(customerJobCounts).filter(c => c > 1).length;
    const repeatCustomerRate = totalCustomersWithJobs ? Math.round((repeatCustomers / totalCustomersWithJobs) * 100) : 0;

    // Busiest day-of-week and hour-of-day, all time — helps staffing decisions.
    const dayOfWeekCounts = [0,0,0,0,0,0,0]; // Sun-Sat
    const hourCounts = Array(24).fill(0);
    (jobs || []).forEach(j => {
      const d = new Date(j.created_at);
      const parts = new Intl.DateTimeFormat('en-US', { timeZone: BUSINESS_TZ, weekday: 'short', hour: 'numeric', hour12: false }).formatToParts(d);
      const map = {}; parts.forEach(p => map[p.type] = p.value);
      const dayIdx = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].indexOf(map.weekday);
      const hour = parseInt(map.hour) % 24;
      if (dayIdx >= 0) dayOfWeekCounts[dayIdx]++;
      hourCounts[hour]++;
    });
    const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    const busiestDay = dayNames[dayOfWeekCounts.indexOf(Math.max(...dayOfWeekCounts))];
    const busiestHour = hourCounts.indexOf(Math.max(...hourCounts));

    // 30-day trend — same shape as last7 but extended, for a longer-range view.
    const last30 = [];
    for (let i = 29; i >= 0; i--) {
      const d = new Date(nowEastern); d.setDate(nowEastern.getDate() - i);
      const ds = dateInBusinessTz(d);
      const dayJobs = jobs?.filter(j => j.job_date === ds) || [];
      last30.push({ date: ds, total: dayJobs.length, done: dayJobs.filter(j=>j.status==='done').length });
    }

    res.json({
      today: todayJobs, todayTotal: todayJobs.length, weekTotal: weekJobs.length, monthTotal: monthJobs.length,
      statusCounts, typeCounts, techPerf, last7, revenue: revenueData, totalJobs: jobs?.length || 0,
      // Today, Done, and Cancelled are all scoped to TODAY specifically now —
      // Revenue/Outstanding stay week-scoped, per Hassan, since those two are
      // fine as a weekly view.
      cancelled: todayJobs.filter(j => j.status === 'cancelled').length,
      // "Done This Week" was previously read from weekTotal — literally "how
      // many jobs came in this week," nothing to do with completion status at
      // all. This actually counts jobs completed within that same week window.
      doneCount: todayJobs.filter(j => j.status === 'done').length,
      growth, avgJobValueTrend, avgResponseMinutes, repeatCustomerRate, busiestDay, busiestHour, last30
    });
  } catch(e) {
    console.error('/api/analytics/dashboard error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── 12-MONTH PERFORMANCE TREND ────────────────────────────────────────────────
// Month-by-month view of close rate, job volume, and revenue over the last year,
// with month-over-month % change on every metric. Optionally filtered to a single
// tech. This is the "how are we doing, are we growing" view — distinct from the
// day-to-day dashboard, built for understanding trajectory over real time.
app.get('/api/analytics/yearly-trend', authMiddleware, adminOnly, async (req, res) => {
  try {
  const techIdRaw = req.query.tech_id || null;
    // "former:<name>" pseudo-IDs select a former tech (no CRM account) by name.
    const formerName = techIdRaw && techIdRaw.startsWith('former:') ? techIdRaw.slice(7) : null;
    const techId = formerName ? null : techIdRaw;
    // Comma-separated list of tech IDs to exclude from the "all techs" view — lets
    // Hassan untick specific techs to see growth trends without their numbers.
    // Entries prefixed "former:" exclude former techs (matched by tech_name on
    // jobs that have no CRM tech account).
    const excludeRaw = (req.query.exclude_tech_ids || '').split(',').map(s => s.trim()).filter(Boolean);
    const excludeTechIds = excludeRaw.filter(x => !x.startsWith('former:'));
    const excludeFormerNames = excludeRaw.filter(x => x.startsWith('former:')).map(x => x.slice(7));
    const nowE = nowInBusinessTz();

    let jobs = await fetchAllRows(() => {
      let q = supabase.from('jobs').select('id,status,job_date,created_at,tech_id,tech_name,invoice_id');
      if (techId) q = q.eq('tech_id', techId);
      if (formerName) q = q.is('tech_id', null).eq('tech_name', formerName);
      return q;
    });
    if (!techId && !formerName && excludeTechIds.length) jobs = (jobs || []).filter(j => !excludeTechIds.includes(j.tech_id));
    if (!techId && !formerName && excludeFormerNames.length) jobs = (jobs || []).filter(j => j.tech_id || !excludeFormerNames.includes(j.tech_name));

    let invoices = await fetchAllRows(() => {
      let q = supabase.from('invoices').select('id,total,status,invoice_date,tech_id,tech_name,job_id');
      if (formerName) q = q.is('tech_id', null).eq('tech_name', formerName);
      return q;
    });
    if (!techId && !formerName && excludeTechIds.length) invoices = (invoices || []).filter(i => !excludeTechIds.includes(i.tech_id));
    if (!techId && !formerName && excludeFormerNames.length) invoices = (invoices || []).filter(i => i.tech_id || !excludeFormerNames.includes(i.tech_name));

    // Period selection: ?from=YYYY-MM&to=YYYY-MM for a custom month range,
    // or ?months=N for the last N months. Default: last 12 months.
    const fromParam = /^\d{4}-\d{2}$/.test(req.query.from || '') ? req.query.from : null;
    const toParam = /^\d{4}-\d{2}$/.test(req.query.to || '') ? req.query.to : null;
    const monthsParam = Math.min(36, Math.max(1, parseInt(req.query.months) || 12));
    let series = [];
    if (fromParam && toParam) {
      let [fy, fm] = fromParam.split('-').map(Number);
      const [ty, tm] = toParam.split('-').map(Number);
      let guard = 0;
      while ((fy < ty || (fy === ty && fm <= tm)) && guard++ < 36) {
        series.push(new Date(fy, fm - 1, 1));
        fm++; if (fm > 12) { fm = 1; fy++; }
      }
    } else {
      for (let i = monthsParam - 1; i >= 0; i--) series.push(new Date(nowE.getFullYear(), nowE.getMonth() - i, 1));
    }

    const months = [];
    for (const m of series) {
      const monthStart = new Date(m.getFullYear(), m.getMonth(), 1);
      const monthEnd = new Date(m.getFullYear(), m.getMonth() + 1, 0, 23, 59, 59);

      const monthJobsList = (jobs || []).filter(j => {
        const jd = new Date(j.job_date || j.created_at);
        return jd >= monthStart && jd <= monthEnd;
      });
      const closed = monthJobsList.filter(j => j.status === 'done').length;
      const total = monthJobsList.length;
      const closeRate = total ? Math.round((closed / total) * 100) : 0;

      const jobIdsThisMonth = new Set(monthJobsList.map(j => j.id));
      const monthInvoices = (invoices || []).filter(inv => {
        if (techId && inv.tech_id !== techId) return false;
        if (inv.status !== 'paid') return false;
        const id = new Date(inv.invoice_date);
        return id >= monthStart && id <= monthEnd;
      });
      const revenue = monthInvoices.reduce((a, inv) => a + (inv.total || 0), 0);

      months.push({
        label: m.toLocaleDateString('en-US', { month: 'short', year: '2-digit' }),
        year: m.getFullYear(), month: m.getMonth(),
        total_jobs: total, closed_jobs: closed, close_rate: closeRate, revenue: Math.round(revenue * 100) / 100
      });
    }

    // Month-over-month % change on every metric, vs the previous month in the series
    function pct(curr, prev) { if (!prev) return curr > 0 ? 100 : 0; return Math.round(((curr - prev) / prev) * 100); }
    const trend = months.map((m, i) => {
      const prev = months[i - 1];
      return {
        ...m,
        jobs_change_pct: prev ? pct(m.total_jobs, prev.total_jobs) : null,
        close_rate_change_pct: prev ? pct(m.close_rate, prev.close_rate) : null,
        revenue_change_pct: prev ? pct(m.revenue, prev.revenue) : null
      };
    });

    // Year-over-year summary: this year's total so far vs the same months last year,
    // so Hassan can see broader trajectory, not just month-to-month noise.
    const thisYearTotal = trend.reduce((a, m) => a + m.total_jobs, 0);
    const thisYearRevenue = trend.reduce((a, m) => a + m.revenue, 0);
    const avgCloseRate = trend.length ? Math.round(trend.reduce((a, m) => a + m.close_rate, 0) / trend.length) : 0;

    res.json({ trend, summary: { total_jobs_12mo: thisYearTotal, total_revenue_12mo: Math.round(thisYearRevenue * 100) / 100, avg_close_rate_12mo: avgCloseRate } });
  } catch(e) {
    console.error('/api/analytics/yearly-trend error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── DAILY JOB BOARD ──────────────────────────────────────────────────────────
app.get('/api/jobs/daily-board', authMiddleware, async (req, res) => {
  try {
  const date = req.query.date || todayInBusinessTz();
    let query = supabase.from('jobs').select('*').eq('job_date', date).order('created_at');
    // Only actual TECHS get scoped to their own assigned jobs. This used to
    // check `role !== 'admin'`, which wrongly caught dispatch too — a
    // dispatch account's id never matches any job's tech_id, so the daily
    // board silently returned zero rows for every dispatch user, every day,
    // regardless of date. Dispatch should see the full board, same as admin.
    if (req.user.role === 'tech') query = query.eq('tech_id', req.user.id);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/daily-board error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Fetch ONE job by id — the on-demand fallback for tabs whose in-memory jobs
// cache predates this job's creation. Registered AFTER daily-board so that
// route isn't swallowed as an :id. Tech accounts stay scoped to their own jobs.
app.get('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    let q = supabase.from('jobs').select('*').eq('id', req.params.id);
    if (req.user.role === 'tech') q = q.eq('tech_id', req.user.id);
    const { data, error } = await q.single();
    if (error || !data) return res.status(404).json({ error: 'Job not found' });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// ─── CALL MASKING — INBOUND ROUTING ──────────────────────────────────────────
// When customer calls back the masked number, route to the tech
// ─── TECH DIAL-IN LINE (dedicated voice number) ─────────────────────────────────
// Configured as the Voice webhook of TWILIO_VOICE_NUMBER. Goes straight to the
// extension prompt — this number only ever appears on tech tickets, never to
// customers. The extension handler and bridge are shared with the main line.
app.post('/api/webhooks/voice/tech-line', twilioWebhookAuth, async (req, res) => {
  res.set('Content-Type', 'text/xml');
  try {
    res.send(`<Response><Gather numDigits="3" timeout="8" action="/api/webhooks/voice/extension" method="POST"><Say>Express Lock and Key tech line. Please enter the 3 digit extension for your job, followed by the pound key.</Say></Gather><Say>No input received. Goodbye.</Say></Response>`);
    const { error: techLineInsErr } = await supabase.from('call_recordings').insert({ tech_name: 'Tech line', customer_name: req.body?.From || 'unknown', call_sid: req.body?.CallSid, direction: 'inbound' });
    if (techLineInsErr) console.error('call_recordings insert (tech-line) failed:', techLineInsErr.message);
  } catch(e) {
    console.error('Tech-line webhook error:', e.message);
    if (!res.headersSent) res.send('<Response><Say>We are experiencing technical difficulties. Please contact dispatch. Goodbye.</Say></Response>');
  }
});

app.post('/api/webhooks/voice', twilioWebhookAuth, async (req, res) => {
  const { From, To, CallSid } = req.body;
  res.set('Content-Type', 'text/xml');
  try {
    // Known customer calling back — route straight to whichever tech is currently
    // assigned on their active job, no menu needed. This takes priority over the
    // extension menu since a returning customer shouldn't have to dial anything.
    const { data: customer } = await supabase.from('customers').select('name').eq('phone', From).single();
    if (customer) {
      // Match the job by the caller's actual PHONE NUMBER (From), not by
      // customer_name — this business names most customers generically
      // ("Mrs", "Mr", "Ms"), so matching by name could route an inbound call
      // to a completely different customer's job that happens to share the
      // same generic display name. Phone number is the one truly unique
      // identifier available here.
      const { data: job } = await supabase.from('jobs').select('id,tech_id,tech_name').eq('phone', From).in('status',['assigned','in-progress']).order('created_at',{ascending:false}).limit(1).single();
      if (job?.tech_id) {
        const { data: t } = await supabase.from('users').select('phone,name').eq('id', job.tech_id).single();
        if (t?.phone) {
          await createNotification('inbound_call', `Inbound call from ${customer.name}`, `Customer calling back — routing to ${t.name}`);
          // Pre-create the recording row NOW, while we still reliably know the
          // job — linked by call_sid so the recording webhook (which only gets
          // a CallSid, not a job) can UPDATE this exact row instead of guessing
          // a job_id via fragile name-matching later.
          const { error: preInsErr } = await supabase.from('call_recordings').insert({ job_id: job.id, tech_name: t.name, customer_name: customer.name, call_sid: CallSid, direction: 'inbound' });
          if (preInsErr) console.error('call_recordings pre-insert (callback path) failed:', preInsErr.message);
          return res.send(`<Response><Say>Please hold while we connect you.</Say><Dial record="true" recordingStatusCallback="${PUBLIC_BASE_URL}/api/webhooks/recording"><Number>${t.phone}</Number></Dial></Response>`);
        }
      }
    }

    // Anyone else (techs on any phone, dispatch, etc.) gets the extension menu —
    // no caller-identity check, since whoever has a valid 3-digit code for an
    // active job should be able to use it.
    res.send(`<Response><Gather numDigits="3" timeout="8" action="/api/webhooks/voice/extension" method="POST"><Say>Welcome to Field Pro. Please enter the 3 digit extension for your job, followed by the pound key.</Say></Gather><Say>No input received. Goodbye.</Say></Response>`);
    // Log call (after response — fine, doesn't delay the caller)
    await supabase.from('call_recordings').insert({ tech_name: 'Inbound', customer_name: customer?.name || From, call_sid: CallSid, direction: 'inbound' });
  } catch(e) {
    console.error('Voice webhook error:', e.message);
    if (!res.headersSent) res.send('<Response><Say>We are experiencing technical difficulties. Please try again shortly.</Say></Response>');
  }
});

// Tech entered a 3-digit extension on the IVR menu. Looks up the job, validates
// the extension hasn't expired, and connects the call to the customer's real
// number — which is never spoken or exposed to the tech, only dialed by Twilio.
app.post('/api/webhooks/voice/extension', twilioWebhookAuth, async (req, res) => {
  const { From, Digits, CallSid } = req.body;
  res.set('Content-Type', 'text/xml');
  try {
    const ext = (Digits || '').replace('#', '').padStart(3, '0').slice(-3);

    // .limit(1) + newest-first instead of .single(): if two active jobs ever end
    // up sharing a code (allocation race), .single() ERRORED and every caller got
    // rejected — this way the most recently issued extension always connects.
    const { data: extJobs, error: extErr } = await supabase.from('jobs').select('*').eq('call_extension', ext).eq('extension_active', true).order('extension_created_at', { ascending: false }).limit(1);
    if (extErr) console.error('Extension lookup error for ext', ext, ':', extErr.message);
    const job = extJobs?.[0];

    if (!job) {
      await supabase.from('extension_call_log').insert({ extension: ext, caller_number: From, outcome: 'invalid' });
      return res.send(`<Response><Say>That extension is not valid or has expired. Please contact dispatch. Goodbye.</Say></Response>`);
    }

    const customerPhone = job.phone;
    if (!customerPhone) {
      await supabase.from('extension_call_log').insert({ extension: ext, job_id: job.id, caller_number: From, outcome: 'no_customer_phone' });
      return res.send(`<Response><Say>No customer phone number is on file for this job. Please contact dispatch. Goodbye.</Say></Response>`);
    }

    await supabase.from('jobs').update({ extension_last_used_at: new Date().toISOString() }).eq('id', job.id);
    await supabase.from('extension_call_log').insert({ extension: ext, job_id: job.id, caller_number: From, outcome: 'connected' });
    // job_id was never actually included here before, despite job.id being
    // right there in scope — the recording webhook then had no reliable way
    // to link the finished recording back to this specific job.
    const { error: preInsErr2 } = await supabase.from('call_recordings').insert({ job_id: job.id, tech_name: job.tech_name || 'Tech', customer_name: job.customer_name, call_sid: CallSid, direction: 'outbound' });
    if (preInsErr2) console.error('call_recordings pre-insert (extension path) failed:', preInsErr2.message);

    res.send(`<Response><Say>Connecting you now.</Say><Dial record="true" recordingStatusCallback="${PUBLIC_BASE_URL}/api/webhooks/recording" callerId="${process.env.TWILIO_PHONE_NUMBER}"><Number>${customerPhone}</Number></Dial></Response>`);
  } catch(e) {
    console.error('Extension webhook error for ext', (req.body?.Digits || '?'), 'from', (req.body?.From || '?'), ':', e.message, e.stack);
    if (!res.headersSent) res.send('<Response><Say>We are experiencing technical difficulties. Please contact dispatch. Goodbye.</Say></Response>');
  }
});

// ─── AI CALL SUMMARY ──────────────────────────────────────────────────────────
// Requests a real transcription from Twilio for this recording (if not already
// requested), or generates a genuine AI summary from the actual transcript text
// once it's ready. Requires a Twilio Transcription Configuration to be set up
// once in the Twilio Console — see deploy notes. Until that's configured, this
// returns a clear "not configured" message instead of fabricating a summary.
app.post('/api/recordings/:id/summarize', authMiddleware, async (req, res) => {
  try {
    const { data: rec } = await supabase.from('call_recordings').select('*').eq('id', req.params.id).single();
    if (!rec) return res.status(404).json({ error: 'Recording not found' });

    const { data: configSetting } = await supabase.from('settings').select('value').eq('key', 'twilio_transcription_config_sid').single();
    const configSid = configSetting?.value;
    if (!configSid) {
      return res.status(400).json({ error: 'Transcription is not set up yet. Go to Settings → Call Transcription to configure it.' });
    }

    // Already have a real transcript — summarize the actual words spoken.
    if (rec.transcript_status === 'completed' && rec.transcript_text) {
      const prompt = `Summarize this real phone call transcript for a locksmith business. Call was between ${rec.tech_name || 'a technician'} and ${rec.customer_name || 'a customer'}.\n\nTRANSCRIPT:\n${rec.transcript_text}\n\nProvide: 1) Brief overview of what was discussed, 2) Any commitments or follow-up actions mentioned, 3) Any flags (complaints, pricing disputes, scheduling issues). Keep it concise.`;
      const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY || '', 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
      });
      const aiData = await aiRes.json();
      const summary = aiData.content?.[0]?.text || 'Summary unavailable';
      await supabase.from('call_recordings').update({ call_summary: summary }).eq('id', req.params.id);
      return res.json({ summary, source: 'real_transcript' });
    }

    // Transcription already requested, still processing
    if (rec.transcript_status === 'pending') {
      return res.json({ summary: null, status: 'pending', message: 'Transcription is still processing — usually ready within a few minutes. Check back shortly.' });
    }

    // Not requested yet — submit it to Twilio now
    if (!rec.recording_sid) {
      return res.status(400).json({ error: 'No recording available for this call yet.' });
    }
    const resp = await fetch('https://intelligence.twilio.com/v3/Transcriptions', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ TranscriptionConfigurationSid: configSid, RecordingSid: rec.recording_sid })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.message || 'Twilio transcription request failed');
    await supabase.from('call_recordings').update({ transcription_sid: data.sid, transcript_status: 'pending' }).eq('id', req.params.id);
    res.json({ summary: null, status: 'pending', message: 'Transcription requested — check back in a few minutes.' });
  } catch(e) {
    console.error('/api/recordings/:id/summarize error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Twilio delivers the finished transcript here once processing completes.
app.post('/api/webhooks/transcription', twilioWebhookAuth, async (req, res) => {
  try {
    const { transcription_sid, status, sentences } = req.body;
    const sid = req.body.TranscriptionSid || transcription_sid;
    const transcriptionStatus = req.body.Status || status;
    if (!sid) return res.status(400).send('Missing transcription SID');
    if (transcriptionStatus === 'completed') {
      // Sentence text arrives via webhook payload per Twilio's V3 API
      const text = (req.body.TranscriptText || (Array.isArray(sentences) ? sentences.map(s => s.transcript || s.text).join(' ') : '')) || '';
      await supabase.from('call_recordings').update({ transcript_text: text, transcript_status: 'completed' }).eq('transcription_sid', sid);
    } else if (transcriptionStatus === 'failed') {
      await supabase.from('call_recordings').update({ transcript_status: 'failed' }).eq('transcription_sid', sid);
    }
    res.sendStatus(200);
  } catch(e) {
    console.error('Transcription webhook error:', e.message);
    res.sendStatus(200); // acknowledge anyway so Twilio doesn't retry indefinitely
  }
});


// ─── WORKFLOWS TABLE MIGRATION ────────────────────────────────────────────────
// Fix existing automations table — workflows is the new table
// Both exist side by side


// ─── TECH CALL MASKING SETTINGS ───────────────────────────────────────────────

app.put('/api/users/:id/call-settings', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { use_masking, direct_phone } = req.body;
    const { data, error } = await supabase.from('users')
      .update({ use_masking: use_masking !== undefined ? use_masking : true, direct_phone: direct_phone || null })
      .eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users/:id/call-settings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});

// Updated masked call — respects per-tech masking setting

// ─── AUTO RECEIPT ─────────────────────────────────────────────────────────────
// NOTE: Review link intentionally NOT included in SMS. Our A2P 10DLC campaign
// is registered as transactional-only (Customer Care) with an explicit "no
// review-solicitation" declaration. Sending review requests by SMS would
// violate the registration. Review links belong on the receipt web page instead.

app.post('/api/jobs/:id/auto-close-receipt', authMiddleware, async (req, res) => {
  try {
    const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    const { data: inv } = await supabase.from('invoices').select('*').eq('job_id', req.params.id).single();
    const { data: customer } = await supabase.from('customers').select('*').eq('id', job.customer_id).single();
    const { data: s } = await supabase.from('settings').select('key,value');
    const settings = {}; s?.forEach(x => settings[x.key] = x.value);
    const bizName = settings.business_name || 'Express Lock&Key';
    if (!customer?.phone) return res.json({ success: false, reason: 'No customer phone' });
    let msg = `Hi ${job.customer_name || customer.name}! Your job with ${bizName} is complete.`;
    if (inv) {
      const token = await ensureReceiptToken(inv.id);
      const link = `${req.protocol}://${req.get('host')}/receipt/${token}`;
      msg += ` Here's your receipt: ${link}`;
    }
    msg += ` Thank you for choosing us!`;
    const finalMsg = await appendComplianceFooterIfFirstContact(customer.phone, msg);
    await twilioClient.messages.create({ body: finalMsg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
    if (inv) await supabase.from('invoices').update({ receipt_sent: true }).eq('job_id', req.params.id);
    res.json({ success: true, sent_to: customer.phone });
  } catch(e) {
    console.error('/api/jobs/:id/auto-close-receipt error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
  }
});


// ─── FINAL REGISTRATIONS — MUST STAY AT THE ABSOLUTE BOTTOM OF THIS FILE ───────
// 0) JSON 404 for any /api path that matched nothing above. Without this, an
//    unknown or mistyped API route falls into the SPA catch-all and returns
//    index.html — which the frontend then fails to parse as JSON with the
//    infamous "Unexpected token '<'" error. A clear JSON 404 makes such bugs
//    obvious in one glance at the Network tab instead of masquerading as data
//    corruption.
app.use('/api', (req, res) => {
  res.status(404).json({ error: `No such API route: ${req.method} /api${req.path}` });
});

// 1) SPA catch-all: serves the frontend for any non-API GET. Registered last so
//    it can never shadow an API route (see the note where these used to live).
app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 2) Express error handler — must be after all routes; Express only treats a
//    4-argument function as an error handler.
app.use((err, req, res, next) => {
  console.error('Express error handler caught:', err?.message, err?.stack);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error' });
});

// 3) Start the server.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FieldPro CRM running on port ${PORT}`);
  startAlertEngine().catch(e => console.error('Alert engine failed to start:', e.message));
});
