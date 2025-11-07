import { validateClients, validateTransactions } from './lib/validate.js';
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

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Config (minimal) ----------
const VERIFY_TTL_MIN = parseInt(process.env.VERIFY_TTL_MIN || '60', 10);
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev_cookie_secret_change_me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_ID_STARTER = process.env.STRIPE_PRICE_ID_STARTER || '';
const STRIPE_PRICE_ID_TEAM = process.env.STRIPE_PRICE_ID_TEAM || '';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Build absolute origin from request
function originOf(req) {
  const proto =
    (req.headers['x-forwarded-proto'] && String(req.headers['x-forwarded-proto']).split(',')[0]) ||
    req.protocol ||
    'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}

// ---------- Signed cookie helpers ----------
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
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good)) ? value : null;
}

// ---------- In-memory verify store ----------
const verifyStore = new Map(); // token -> { zipBuffer, manifest, exp }
function newToken() {
  return crypto.randomBytes(16).toString('hex') + crypto.randomBytes(16).toString('hex');
}

// ---------- App ----------
const app = express();
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ---------- Middleware (order matters) ----------
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

// Static assets
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
app.use(baseLimiter);

// Uploads (memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024, files: 2 }
});

// ---------- Health ----------
app.get('/healthz', (_req, res) => res.send('ok'));

// ---------- Marketing nice URLs ----------
app.get('/', (req, res) => {
  // If paid cookie exists, go straight to app; otherwise landing
  const paid = getPaidClaim(req);
  if (paid) return res.redirect(302, '/app');
  // serve marketing index
  res.redirect(302, '/site/index.html');
});
app.get('/features', (_req, res) => res.redirect(302, '/site/features.html'));
app.get('/faq', (_req, res) => res.redirect(302, '/site/faq.html'));
app.get('/pricing', (_req, res) => res.redirect(302, '/site/pricing.html'));

// ---------- Paywall ----------
function getPaidClaim(req) {
  const raw = req.cookies?.tr_paid;
  if (!raw) return null;
  const val = verifySigned(raw);
  if (!val) return null;
  try {
    const obj = JSON.parse(val);
    if (obj.sub !== 'paid' || typeof obj.exp !== 'number') return null;
    if (Date.now() > obj.exp) return null;
    return obj;
  } catch {
    return null;
  }
}

function requirePaid(req, res, next) {
  const claim = getPaidClaim(req);
  if (claim) return next();
  return res.redirect(302, '/pricing');
}

// App UI (protected)
app.get('/app', requirePaid, (_req, res) => res.render('app'));

// ---------- Stripe: create checkout & return ----------
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
      cancel_url: `${base}/pricing?canceled=1}`,
      allow_promotion_codes: true
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: 'Stripe error' });
  }
});

// User returns here; we verify the session with Stripe and set cookie
app.get('/billing/return', async (req, res) => {
  try {
    const session_id = String(req.query.session_id || '');
    if (!session_id || !stripe) return res.redirect(302, '/pricing?error=missing_session');
    const session = await stripe.checkout.sessions.retrieve(session_id);

    // Accept payment or subscription states
    const paidOk =
      (session.mode === 'payment' && session.payment_status === 'paid') ||
      (session.mode === 'subscription' && session.status === 'complete');

    if (!paidOk) return res.redirect(302, '/pricing?error=unpaid');

    // Issue signed cookie for 30 days
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
  upload.fields([
    { name: 'clients', maxCount: 1 },
    { name: 'transactions', maxCount: 1 }
  ]),
  (req, res) => {
    try {
      const clientsFile = req.files?.clients?.[0];
      const txFile = req.files?.transactions?.[0];
      if (!clientsFile || !txFile)
        return res.status(400).json({ ok: false, error: 'Both files required: clients, transactions' });

      const clientsCsv = csvParse(clientsFile.buffer.toString('utf8'), { columns: true, skip_empty_lines: true });
      const txCsv = csvParse(txFile.buffer.toString('utf8'), { columns: true, skip_empty_lines: true });

      const { clients, clientHeaderMap } = normalizeClients(clientsCsv);
      const { txs, txHeaderMap, rejects, lookback } = normalizeTransactions(txCsv);

      res.json({
        ok: true,
        counts: { clients: clients.length, txs: txs.length, rejects: rejects.length },
        clientHeaderMap,
        txHeaderMap,
        rejects,
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
  upload.fields([
    { name: 'clients', maxCount: 1 },
    { name: 'transactions', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const clientsFile = req.files?.clients?.[0];
      const txFile = req.files?.transactions?.[0];
      if (!clientsFile || !txFile)
        return res.status(400).json({ error: 'Both Clients.csv and Transactions.csv are required.' });

      const clientsCsv = csvParse(clientsFile.buffer.toString('utf8'), { columns: true, skip_empty_lines: true });
      const txCsv = csvParse(txFile.buffer.toString('utf8'), { columns: true, skip_empty_lines: true });

      const { clients, clientHeaderMap } = normalizeClients(clientsCsv);
      const { txs, txHeaderMap, rejects, lookback } = normalizeTransactions(txCsv);

      const { scores, rulesMeta } = await scoreAll(clients, txs, lookback);
      const cases = buildCases(txs, lookback);

      const files = {
        'clients.json': Buffer.from(JSON.stringify(clients, null, 2)),
        'transactions.json': Buffer.from(JSON.stringify(txs, null, 2)),
        'cases.json': Buffer.from(JSON.stringify(cases, null, 2)),
        'program.html': Buffer.from(renderProgramHTML(rulesMeta, clientHeaderMap, txHeaderMap, rejects))
      };

      const manifest = buildManifest(files, rulesMeta);
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

function renderProgramHTML(rulesMeta, clientHeaderMap, txHeaderMap, rejects) {
  return [
    '<!doctype html><meta charset="utf-8"><title>TrancheReady Evidence</title>',
    '<style>body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;line-height:1.55;padding:24px;color:#DCE6FF;background:#0A1730} code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0A1730;border:1px solid #213058;border-radius:8px;padding:10px;display:block;overflow:auto}</style>',
    '<h1>TrancheReady Evidence</h1>',
    `<p>Generated: ${new Date().toISOString()}</p>`,
    '<h2>Ruleset</h2>',
    `<pre>${escapeHtml(JSON.stringify(rulesMeta, null, 2))}</pre>`,
    '<h2>Header Mapping</h2>',
    `<pre>${escapeHtml(JSON.stringify({ clients: clientHeaderMap, transactions: txHeaderMap }, null, 2))}</pre>`,
    '<h2>Row Rejects</h2>',
    `<pre>${escapeHtml(JSON.stringify(rejects, null, 2))}</pre>`
  ].join('');
}
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- Verify & Download (public) ----------
app.get('/verify/:token', (req, res) => {
  const entry = verifyStore.get(req.params.token);
  if (!entry || Date.now() > entry.exp) return res.status(404).send('Link expired or not found.');
  res.render('verify', { manifest: entry.manifest });
});
app.get('/download/:token', (req, res) => {
  const entry = verifyStore.get(req.params.token);
  if (!entry || Date.now() > entry.exp) return res.status(404).send('Link expired or not found.');
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="trancheready-evidence.zip"');
  res.send(entry.zipBuffer);
});

// ---------- 404 ----------
app.use((_req, res) => res.status(404).send('Not Found'));

// ---------- Start ----------
const PORT = parseInt(process.env.PORT || '10000', 10);
app.listen(PORT, () => console.log('listening on', PORT));
