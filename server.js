import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import fs from 'fs';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import Stripe from 'stripe';
import { parse as csvParse } from 'csv-parse/sync';

import { normalizeClients, normalizeTransactions } from './lib/csv-normalize.js';
import { scoreAll } from './lib/rules.js';
import { buildCases } from './lib/cases.js';
import { buildManifest } from './lib/manifest.js';
import { zipNamedBuffers } from './lib/zip.js';
import { validateClients, validateTransactions } from './lib/validate.js';

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Config ----------
const VERIFY_TTL_MIN = parseInt(process.env.VERIFY_TTL_MIN || '60', 10);
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev_cookie_secret_change_me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_ID_STARTER = process.env.STRIPE_PRICE_ID_STARTER || '';
const STRIPE_PRICE_ID_TEAM = process.env.STRIPE_PRICE_ID_TEAM || '';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Build ID used for watermark/provenance (stable across process lifetime)
const BUILD_ID = process.env.BUILD_ID || crypto.randomBytes(6).toString('hex');

// ---------- Helpers ----------
function originOf(req) {
  const proto =
    (req.headers['x-forwarded-proto'] && String(req.headers['x-forwarded-proto']).split(',')[0]) ||
    req.protocol ||
    'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}

// Signed cookie
function sign(value) {
  const h = crypto.createHmac('sha256', COOKIE_SECRET).update(value).digest('hex');
  return `${value}.${h}`;
}
function verifySigned(signed) {
  const idx = signed.lastIndexOf('.');
  if (idx < 0) return null;
  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const good = crypto.createHmac('sha256', COOKIE_SECRET).update(value).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good)) ? value : null;
  } catch { return null; }
}
function parseClaim(raw) {
  const val = raw && verifySigned(raw);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

// Owner paid cookie (from Stripe return)
function getOwnerClaim(req) {
  const claim = parseClaim(req.cookies?.tr_paid);
  if (!claim || claim.sub !== 'paid' || Date.now() > (claim.exp || 0)) return null;
  return claim; // { sub:'paid', sid, exp }
}

// Seat cookie (from invite)
function getSeatClaim(req) {
  const claim = parseClaim(req.cookies?.tr_seat);
  if (!claim || claim.sub !== 'seat' || Date.now() > (claim.exp || 0)) return null;
  return claim; // { sub:'seat', team_id, role:'member', exp }
}

// Accept either owner (paid) or seat (member)
function getAccess(req) {
  const owner = getOwnerClaim(req);
  const seat = getSeatClaim(req);
  if (owner) return { role: 'owner', owner, seat: null };
  if (seat)  return { role: 'member', owner: null, seat };
  return null;
}
function requirePaid(req, res, next) {
  const acc = getAccess(req);
  if (acc) { req.access = acc; return next(); }
  return res.redirect(302, '/pricing');
}

// Team id (stable per owner). We derive a deterministic id from session id (sid) when available.
function teamIdForOwner(ownerClaim) {
  const sid = ownerClaim?.sid || 'local';
  return crypto.createHash('sha256').update(String(sid)).digest('hex').slice(0, 24);
}

// In-memory verify store
const verifyStore = new Map(); // token -> { zipBuffer, manifest, exp }
function newToken() {
  return crypto.randomBytes(16).toString('hex') + crypto.randomBytes(16).toString('hex');
}

// ---------- Express ----------
const app = express();
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware (order matters)
app.use(compression());
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"]
      }
    }
  })
);
app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '1h', etag: true }));
app.use('/site', express.static(path.join(__dirname, 'public', 'site'), { maxAge: '30m', etag: true }));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(
  cors({
    origin: (_origin, cb) => cb(null, true),
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'X-Requested-With']
  })
);

const baseLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
const heavyLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 40 });
const dlLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });
app.use(baseLimiter);

// Uploads (memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024, files: 2 }
});

// ---------- Health ----------
app.get('/healthz', (_req, res) => res.send('ok'));

// ---------- Marketing ----------
app.get('/', (req, res) => {
  const acc = getAccess(req);
  if (acc) return res.redirect(302, '/app');
  return res.redirect(302, '/site/index.html');
});
app.get('/features', (_req, res) => res.redirect(302, '/site/features.html'));
app.get('/faq', (_req, res) => res.redirect(302, '/site/faq.html'));
app.get('/pricing', (_req, res) => res.redirect(302, '/site/pricing.html'));

// ---------- Stripe checkout ----------
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    if (!stripe) return res.status(400).json({ error: 'Payments not configured.' });
    const plan = String(req.body?.plan || 'starter').toLowerCase();
    const priceId = plan === 'team' ? STRIPE_PRICE_ID_TEAM : STRIPE_PRICE_ID_STARTER;
    if (!priceId) return res.status(400).json({ error: 'Missing price id for plan.' });

    const base = originOf(req);
    const session = await stripe.checkout.sessions.create({
      mode: plan === 'team' ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${base}/billing/return?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}/pricing?canceled=1`,
      allow_promotion_codes: true
    });
    res.json({ url: session.url });
  } catch {
    res.status(500).json({ error: 'Stripe error' });
  }
});

app.get('/billing/return', async (req, res) => {
  try {
    const session_id = String(req.query.session_id || '');
    if (!session_id || !stripe) return res.redirect(302, '/pricing?error=missing_session');
    const session = await stripe.checkout.sessions.retrieve(session_id);

    const paidOk =
      (session.mode === 'payment' && session.payment_status === 'paid') ||
      (session.mode === 'subscription' && session.status === 'complete');

    if (!paidOk) return res.redirect(302, '/pricing?error=unpaid');

    // Issue owner cookie
    const claim = JSON.stringify({ sub: 'paid', sid: session_id, exp: Date.now() + 30 * 24 * 3600 * 1000 });
    const signed = sign(claim);
    res.cookie('tr_paid', signed, {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      maxAge: 30 * 24 * 3600 * 1000
    });
    return res.redirect(302, '/app');
  } catch {
    return res.redirect(302, '/pricing?error=verify_failed');
  }
});

// ---------- Team seats (magic links, no DB) ----------
app.get('/team', requirePaid, (req, res) => {
  const owner = req.access.role === 'owner' ? req.access.owner : null;
  const team_id = teamIdForOwner(owner);
  res.render('team', { team_id, build_id: BUILD_ID });
});

// Create invite token (owner only)
app.post('/team/invite', requirePaid, (req, res) => {
  if (req.access.role !== 'owner') return res.status(403).json({ error: 'Only owner can invite.' });
  const owner = req.access.owner;
  const team_id = teamIdForOwner(owner);
  // Invite token expires in 7 days
  const payload = JSON.stringify({ sub: 'invite', team_id, exp: Date.now() + 7 * 24 * 3600 * 1000 });
  const token = sign(payload);
  const base = originOf(req);
  res.json({ invite_url: `${base}/join/${encodeURIComponent(token)}`, team_id });
});

// Redeem invite (sets seat cookie)
app.get('/join/:token', (req, res) => {
  const token = req.params.token || '';
  const val = verifySigned(token);
  if (!val) return res.status(400).render('error', { title: 'Invalid invite', message: 'This invite link is invalid.' });
  let obj;
  try { obj = JSON.parse(val); } catch { obj = null; }
  if (!obj || obj.sub !== 'invite' || Date.now() > (obj.exp || 0)) {
    return res.status(400).render('error', { title: 'Expired invite', message: 'This invite link has expired.' });
  }
  const seatClaim = JSON.stringify({ sub: 'seat', team_id: obj.team_id, role: 'member', exp: Date.now() + 30 * 24 * 3600 * 1000 });
  const seatSigned = sign(seatClaim);
  res.cookie('tr_seat', seatSigned, { httpOnly: true, sameSite: 'lax', secure: true, maxAge: 30 * 24 * 3600 * 1000 });
  return res.redirect(302, '/app');
});

// ---------- App UI (protected) ----------
app.get('/app', requirePaid, (_req, res) => res.render('app'));

// ---------- Templates ----------
app.get('/api/templates', (req, res) => {
  const name = String(req.query.name || '').toLowerCase();
  const file = name === 'transactions' ? 'Transactions.template.csv' : 'Clients.template.csv';
  const full = path.join(__dirname, 'public', 'templates', file);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'Template not found' });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${file}"`);
  fs.createReadStream(full).pipe(res);
});

// ---------- Validate ----------
app.post(
  '/api/validate',
  requirePaid,
  heavyLimiter,
  upload.fields([{ name: 'clients', maxCount: 1 }, { name: 'transactions', maxCount: 1 }]),
  (req, res) => {
    try {
      const clientsFile = req.files?.clients?.[0];
      const txFile = req.files?.transactions?.[0];
      if (!clientsFile || !txFile)
        return res.status(400).json({ ok: false, error: 'Both files required: clients, transactions' });

      const clientsCsv = csvParse(clientsFile.buffer.toString('utf8'), {
        columns: true, skip_empty_lines: true, relax_column_count: true
      });
      const txCsv = csvParse(txFile.buffer.toString('utf8'), {
        columns: true, skip_empty_lines: true, relax_column_count: true
      });

      const { clients, clientHeaderMap } = normalizeClients(clientsCsv);
      const { txs, txHeaderMap, rejects, lookback } = normalizeTransactions(txCsv);

      const clientIssues = validateClients(clients);
      const txIssues = validateTransactions(txs);

      res.json({
        ok: clientIssues.length === 0 && txIssues.length === 0 && rejects.length === 0,
        counts: { clients: clients.length, txs: txs.length, rejects: rejects.length },
        headerMaps: { clients: clientHeaderMap, transactions: txHeaderMap },
        issues: { clients: clientIssues, transactions: txIssues, rejects },
        lookback
      });
    } catch {
      res.status(500).json({ ok: false, error: 'Validation failed' });
    }
  }
);

// ---------- Upload → Evidence ----------
app.post(
  '/upload',
  requirePaid,
  heavyLimiter,
  upload.fields([{ name: 'clients', maxCount: 1 }, { name: 'transactions', maxCount: 1 }]),
  async (req, res) => {
    try {
      const clientsFile = req.files?.clients?.[0];
      const txFile = req.files?.transactions?.[0];
      if (!clientsFile || !txFile)
        return res.status(400).json({ error: 'Both Clients.csv and Transactions.csv are required.' });

      const clientsCsv = csvParse(clientsFile.buffer.toString('utf8'), {
        columns: true, skip_empty_lines: true, relax_column_count: true
      });
      const txCsv = csvParse(txFile.buffer.toString('utf8'), {
        columns: true, skip_empty_lines: true, relax_column_count: true
      });

      const { clients, clientHeaderMap } = normalizeClients(clientsCsv);
      const { txs, txHeaderMap, rejects, lookback } = normalizeTransactions(txCsv);

      // Guard: fail fast if validation has issues
      const clientIssues = validateClients(clients);
      const txIssues = validateTransactions(txs);
      if (clientIssues.length || txIssues.length || rejects.length) {
        return res.status(400).json({
          error: 'Validation errors — fix and try again.',
          issues: { clients: clientIssues, transactions: txIssues, rejects }
        });
      }

      const { scores, rulesMeta } = await scoreAll(clients, txs, lookback);
      const cases = buildCases(txs, lookback);

      const files = {
        'clients.json': Buffer.from(JSON.stringify(clients, null, 2)),
        'transactions.json': Buffer.from(JSON.stringify(txs, null, 2)),
        'cases.json': Buffer.from(JSON.stringify(cases, null, 2)),
        'program.html': Buffer.from(renderProgramHTML(rulesMeta, clientHeaderMap, txHeaderMap, rejects, BUILD_ID))
      };

      // 🔐 Add watermark & build id in manifest
      const manifest = buildManifest(files, rulesMeta, {
        build_id: BUILD_ID,
        watermark: `TrancheReady evidence • Build ${BUILD_ID}`
      });

      const zipBuffer = await zipNamedBuffers({
        ...files,
        'manifest.json': Buffer.from(JSON.stringify(manifest, null, 2))
      });

      const token = newToken();
      const exp = Date.now() + VERIFY_TTL_MIN * 60 * 1000;
      verifyStore.set(token, { zipBuffer, manifest, exp });

      const base = originOf(req);
      res.json({
        ok: true,
        risk: scores,
        verify_url: `${base}/verify/${token}`,
        download_url: `${base}/download/${token}`
      });
    } catch {
      res.status(500).json({ error: 'Processing failed.' });
    }
  }
);

function renderProgramHTML(rulesMeta, clientHeaderMap, txHeaderMap, rejects, buildId) {
  return `<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrancheReady Evidence</title>
<style>
  :root{--ink:#E8F0FF;--muted:#A8B9E3;--line:#213058;--bg:#0A1630;--panel:#0B1733;--radius:14px}
  *{box-sizing:border-box}
  body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;color:var(--ink);background:var(--bg);line-height:1.55}
  .wrap{max-width:900px;margin:24px auto;padding:0 16px}
  .card{background:linear-gradient(180deg,#0B1733,#0B1733);border:1px solid var(--line);border-radius:var(--radius);padding:18px;box-shadow:0 18px 44px rgba(0,12,45,.35);margin-bottom:16px}
  h1,h2{margin:.2rem 0 .6rem}
  .muted{color:var(--muted)}
  pre{white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;background:#0C1733;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto}
  .water{color:#9FB1D8;margin-top:6px;font-size:.92rem}
</style>
<div class="wrap">
  <div class="card">
    <h1>TrancheReady Evidence</h1>
    <p class="muted">Generated: ${new Date().toISOString()}</p>
    <p class="water">Build: ${buildId}</p>
  </div>
  <div class="card">
    <h2>Ruleset</h2>
    <pre>${escapeHtml(JSON.stringify(rulesMeta, null, 2))}</pre>
  </div>
  <div class="card">
    <h2>Header Mapping</h2>
    <pre>${escapeHtml(JSON.stringify({ clients: clientHeaderMap, transactions: txHeaderMap }, null, 2))}</pre>
  </div>
  <div class="card">
    <h2>Row Rejects</h2>
    <pre>${escapeHtml(JSON.stringify(rejects, null, 2))}</pre>
  </div>
</div>`;
}
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- Verify & Download ----------
app.get('/verify/:token', verifyLimiter, (req, res) => {
  const entry = verifyStore.get(req.params.token);
  if (!entry || Date.now() > entry.exp) {
    res.status(404);
    try { return res.render('error', { title: 'Link expired', message: 'This verify link has expired or is invalid.' }); }
    catch { return res.send('Link expired or not found.'); }
  }
  res.render('verify', { manifest: entry.manifest, build_id: BUILD_ID });
});

app.get('/download/:token', dlLimiter, (req, res) => {
  const entry = verifyStore.get(req.params.token);
  if (!entry || Date.now() > entry.exp) {
    res.status(404);
    try { return res.render('error', { title: 'Link expired', message: 'This download link has expired or is invalid.' }); }
    catch { return res.send('Link expired or not found.'); }
  }
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="trancheready-evidence.zip"');
  res.send(entry.zipBuffer);
});

// ---------- 404 & error ----------
app.use((req, res) => {
  res.status(404);
  try { return res.render('error', { title: 'Not found', message: 'The page you requested was not found.' }); }
  catch { return res.send('Not Found'); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500);
  try { return res.render('error', { title: 'Server error', message: 'Please try again shortly.' }); }
  catch { return res.send('Server error'); }
});

// ---------- Start ----------
const PORT = parseInt(process.env.PORT || '10000', 10);
app.listen(PORT, () => console.log('listening on', PORT, 'build', BUILD_ID));
