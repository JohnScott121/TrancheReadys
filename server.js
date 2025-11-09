// server.js — resilient zip import (works with any zip.js export style)
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

// 👇 Resilient import: supports named export, default object, or default function
import * as zipModule from './lib/zip.js';
const zipNamedBuffers =
  // ESM named export
  (zipModule && zipModule.zipNamedBuffers) ||
  // default export is an object with the function
  (zipModule && zipModule.default && zipModule.default.zipNamedBuffers) ||
  // default export is the function itself
  (typeof zipModule?.default === 'function' ? zipModule.default : null);

if (typeof zipNamedBuffers !== 'function') {
  throw new Error(
    'zipNamedBuffers not found. Ensure lib/zip.js exports { zipNamedBuffers } or default export.'
  );
}

import { validateClients, validateTransactions } from './lib/validate.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Config ----------
const VERIFY_TTL_MIN = parseInt(process.env.VERIFY_TTL_MIN || '60', 10);
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev_cookie_secret_change_me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_ID_STARTER = process.env.STRIPE_PRICE_ID_STARTER || '';
const STRIPE_PRICE_ID_TEAM = process.env.STRIPE_PRICE_ID_TEAM || '';
const PRIMARY_DOMAIN = (process.env.PRIMARY_DOMAIN || '').toLowerCase().trim();
const FORCE_HTTPS = (process.env.FORCE_HTTPS || '1') === '1';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Build ID
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
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good)) ? value : null; } catch { return null; }
}
function parseClaim(raw) { const v = raw && verifySigned(raw); try { return v ? JSON.parse(v) : null; } catch { return null; } }
function getOwnerClaim(req) { const c = parseClaim(req.cookies?.tr_paid); if (!c || c.sub !== 'paid' || Date.now() > (c.exp || 0)) return null; return c; }
function getSeatClaim(req) { const c = parseClaim(req.cookies?.tr_seat); if (!c || c.sub !== 'seat' || Date.now() > (c.exp || 0)) return null; return c; }
function getAccess(req) { const owner = getOwnerClaim(req); const seat = getSeatClaim(req); if (owner) return { role:'owner', owner, seat:null }; if (seat) return { role:'member', owner:null, seat }; return null; }
function requirePaid(req, res, next) { const acc = getAccess(req); if (acc) { req.access = acc; return next(); } return res.redirect(302, '/pricing'); }
function teamIdForOwner(ownerClaim) { const sid = ownerClaim?.sid || 'local'; return crypto.createHash('sha256').update(String(sid)).digest('hex').slice(0, 24); }

const verifyStore = new Map();
function newToken(){ return crypto.randomBytes(16).toString('hex') + crypto.randomBytes(16).toString('hex'); }

// ---------- App ----------
const app = express();
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// tiny log
app.use((req,res,next)=>{
  const t=Date.now();
  res.on('finish',()=>console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now()-t}ms`));
  next();
});

// HTTPS + primary domain
app.use((req,res,next)=>{
  const xf = String(req.headers['x-forwarded-proto']||'').split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').toLowerCase();
  if (FORCE_HTTPS && xf && xf !== 'https') return res.redirect(301, `https://${host}${req.originalUrl}`);
  if (PRIMARY_DOMAIN && host && host !== PRIMARY_DOMAIN) return res.redirect(301, `https://${PRIMARY_DOMAIN}${req.originalUrl}`);
  next();
});

app.use(helmet({
  contentSecurityPolicy:{
    useDefaults:true,
    directives:{
      "default-src":["'self'"],
      "script-src":["'self'"],
      "style-src":["'self'","'unsafe-inline'"],
      "img-src":["'self'","data:"],
      "connect-src":["'self'"],
      "object-src":["'none'"],
      "frame-ancestors":["'none'"]
    }
  },
  hsts:{ maxAge:31536000, includeSubDomains:true }
}));
app.use(compression());
app.use('/public', express.static(path.join(__dirname,'public'),{ etag:true, maxAge:'1h' }));
app.use('/site', express.static(path.join(__dirname,'public','site'),{ etag:true, maxAge:'30m' }));
app.use(express.json({ limit:'2mb' }));
app.use(express.urlencoded({ extended:false }));
app.use(cookieParser());
app.use(cors({ origin:(_o,cb)=>cb(null,true), methods:['GET','POST'], allowedHeaders:['Content-Type','X-Requested-With'] }));

const baseLimiter = rateLimit({ windowMs: 15*60*1000, max:300 });
const heavyLimiter = rateLimit({ windowMs: 10*60*1000, max:60 });
const verifyLimiter = rateLimit({ windowMs: 60*1000, max:40 });
const dlLimiter = rateLimit({ windowMs: 60*1000, max:20 });
app.use(baseLimiter);

const upload = multer({ storage: multer.memoryStorage(), limits:{ fileSize:25*1024*1024, files:2 } });

app.get('/healthz', (_req,res)=>res.send('ok'));
app.get('/api/version', (_req,res)=>res.json({ build: BUILD_ID, ttl_min: VERIFY_TTL_MIN }));

// Marketing
app.get('/', (req,res)=>{ const acc = getAccess(req); if (acc) return res.redirect(302,'/app'); return res.redirect(302,'/site/index.html'); });
app.get('/features', (_req,res)=>res.redirect(302,'/site/features.html'));
app.get('/faq', (_req,res)=>res.redirect(302,'/site/faq.html'));
app.get('/pricing', (_req,res)=>res.redirect(302,'/site/pricing.html'));

// Stripe
app.post('/api/create-checkout-session', async (req,res)=>{
  try{
    if (!stripe) return res.status(400).json({ error:'Payments not configured.' });
    const plan = String(req.body?.plan || 'starter').toLowerCase();
    const priceId = plan === 'team' ? STRIPE_PRICE_ID_TEAM : STRIPE_PRICE_ID_STARTER;
    if (!priceId) return res.status(400).json({ error:'Missing price id for plan.' });
    const base = originOf(req);
    const session = await stripe.checkout.sessions.create({
      mode: plan === 'team' ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${base}/billing/return?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}/pricing?canceled=1`,
      allow_promotion_codes: true
    });
    res.json({ url: session.url });
  }catch(e){ console.error(e); res.status(500).json({ error:'Stripe error' }); }
});
app.get('/billing/return', async (req,res)=>{
  try{
    const session_id = String(req.query.session_id || '');
    if (!session_id || !stripe) return res.redirect(302, '/pricing?error=missing_session');
    const s = await stripe.checkout.sessions.retrieve(session_id);
    const ok = (s.mode==='payment' && s.payment_status==='paid') || (s.mode==='subscription' && s.status==='complete');
    if (!ok) return res.redirect(302,'/pricing?error=unpaid');
    const claim = JSON.stringify({ sub:'paid', sid: session_id, exp: Date.now()+30*24*3600*1000 });
    res.cookie('tr_paid', sign(claim), { httpOnly:true, sameSite:'lax', secure:true, maxAge:30*24*3600*1000 });
    return res.redirect(302,'/app');
  }catch(e){ console.error(e); return res.redirect(302,'/pricing?error=verify_failed'); }
});

// Team seats
app.get('/team', requirePaid, (req,res)=>{ const owner = req.access.role==='owner'?req.access.owner:null; const team_id = teamIdForOwner(owner); res.render('team',{ team_id, build_id: BUILD_ID }); });
app.post('/team/invite', requirePaid, (req,res)=>{ if (req.access.role!=='owner') return res.status(403).json({ error:'Only owner can invite.' }); const team_id = teamIdForOwner(req.access.owner); const payload = JSON.stringify({ sub:'invite', team_id, exp: Date.now()+7*24*3600*1000 }); const token = sign(payload); const base = originOf(req); res.json({ invite_url:`${base}/join/${encodeURIComponent(token)}`, team_id }); });
app.get('/join/:token', (req,res)=>{ const val = verifySigned(req.params.token || ''); if (!val) return res.status(400).render('error',{ title:'Invalid invite', message:'This invite link is invalid.' }); let obj; try{ obj = JSON.parse(val); }catch{ obj=null; } if (!obj || obj.sub!=='invite' || Date.now()>(obj.exp||0)) return res.status(400).render('error',{ title:'Expired invite', message:'This invite link has expired.' }); const seat = JSON.stringify({ sub:'seat', team_id: obj.team_id, role:'member', exp: Date.now()+30*24*3600*1000 }); res.cookie('tr_seat', sign(seat), { httpOnly:true, sameSite:'lax', secure:true, maxAge:30*24*3600*1000 }); return res.redirect(302,'/app'); });

// App
app.get('/app', requirePaid, (_req,res)=>res.render('app'));

// Templates
app.get('/api/templates', (req,res)=>{
  const name = String(req.query.name || '').toLowerCase();
  const file = name === 'transactions' ? 'Transactions.template.csv' : 'Clients.template.csv';
  const full = path.join(__dirname, 'public', 'templates', file);
  if (!fs.existsSync(full)) return res.status(404).json({ error:'Template not found' });
  res.setHeader('Content-Type','text/csv; charset=utf-8');
  res.setHeader('Content-Disposition',`attachment; filename="${file}"`);
  fs.createReadStream(full).pipe(res);
});

// Validate
app.post('/api/validate', requirePaid, rateLimit({windowMs:10*60*1000,max:60}),
  upload.fields([{ name:'clients',maxCount:1 }, { name:'transactions',maxCount:1 }]),
  (req,res)=>{
    try{
      const clientsFile = req.files?.clients?.[0];
      const txFile = req.files?.transactions?.[0];
      if (!clientsFile || !txFile) return res.status(400).json({ ok:false, error:'Both files required: clients, transactions' });

      const clientsCsv = csvParse(clientsFile.buffer.toString('utf8'),{ columns:true, skip_empty_lines:true, relax_column_count:true });
      const txCsv = csvParse(txFile.buffer.toString('utf8'),{ columns:true, skip_empty_lines:true, relax_column_count:true });

      const { clients, clientHeaderMap } = normalizeClients(clientsCsv);
      const { txs, txHeaderMap, rejects, lookback } = normalizeTransactions(txCsv);

      const clientIssues = validateClients(clients);
      const txIssues = validateTransactions(txs);

      res.json({
        ok: clientIssues.length===0 && txIssues.length===0 && rejects.length===0,
        counts:{ clients:clients.length, txs:txs.length, rejects:rejects.length },
        headerMaps:{ clients:clientHeaderMap, transactions:txHeaderMap },
        issues:{ clients:clientIssues, transactions:txIssues, rejects },
        lookback
      });
    }catch{
      res.status(500).json({ ok:false, error:'Validation failed' });
    }
  }
);

// Upload → Evidence
app.post('/upload', requirePaid, rateLimit({windowMs:10*60*1000,max:60}),
  upload.fields([{ name:'clients',maxCount:1 }, { name:'transactions',maxCount:1 }]),
  async (req,res)=>{
    try{
      const clientsFile = req.files?.clients?.[0];
      const txFile = req.files?.transactions?.[0];
      if (!clientsFile || !txFile) return res.status(400).json({ error:'Both Clients.csv and Transactions.csv are required.' });

      const clientsCsv = csvParse(clientsFile.buffer.toString('utf8'),{ columns:true, skip_empty_lines:true, relax_column_count:true });
      const txCsv = csvParse(txFile.buffer.toString('utf8'),{ columns:true, skip_empty_lines:true, relax_column_count:true });

      const { clients, clientHeaderMap } = normalizeClients(clientsCsv);
      const { txs, txHeaderMap, rejects, lookback } = normalizeTransactions(txCsv);

      const clientIssues = validateClients(clients);
      const txIssues = validateTransactions(txs);
      if (clientIssues.length || txIssues.length || rejects.length) {
        return res.status(400).json({ error:'Validation errors — fix and try again.', issues:{ clients:clientIssues, transactions:txIssues, rejects } });
      }

      const { scores, rulesMeta } = await scoreAll(clients, txs, lookback);
      const cases = buildCases(txs, lookback);

      const files = {
        'clients.json': Buffer.from(JSON.stringify(clients,null,2)),
        'transactions.json': Buffer.from(JSON.stringify(txs,null,2)),
        'cases.json': Buffer.from(JSON.stringify(cases,null,2)),
        'program.html': Buffer.from(renderProgramHTML(rulesMeta, clientHeaderMap, txHeaderMap, rejects, BUILD_ID))
      };

      const manifest = buildManifest(files, rulesMeta, {
        build_id: BUILD_ID,
        watermark: `TrancheReady evidence • Build ${BUILD_ID}`
      });

      const zipBuffer = await zipNamedBuffers({
        ...files,
        'manifest.json': Buffer.from(JSON.stringify(manifest,null,2))
      });

      const token = newToken();
      const exp = Date.now() + VERIFY_TTL_MIN*60*1000;
      verifyStore.set(token, { zipBuffer, manifest, exp });

      const base = originOf(req);
      res.json({ ok:true, risk:scores, verify_url:`${base}/verify/${token}`, download_url:`${base}/download/${token}` });
    }catch{
      res.status(500).json({ error:'Processing failed.' });
    }
  }
);

function renderProgramHTML(rulesMeta, clientHeaderMap, txHeaderMap, rejects, buildId){
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
function escapeHtml(s){ return s.replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// Verify & download
app.get('/verify/:token', verifyLimiter, (req,res)=>{
  const entry = verifyStore.get(req.params.token);
  if (!entry || Date.now() > entry.exp) {
    res.status(404);
    try { return res.render('error',{ title:'Link expired', message:'This verify link has expired or is invalid.' }); }
    catch { return res.send('Link expired or not found.'); }
  }
  res.render('verify',{ manifest: entry.manifest, build_id: BUILD_ID });
});
app.get('/download/:token', dlLimiter, (req,res)=>{
  const entry = verifyStore.get(req.params.token);
  if (!entry || Date.now() > entry.exp) {
    res.status(404);
    try { return res.render('error',{ title:'Link expired', message:'This download link has expired or is invalid.' }); }
    catch { return res.send('Link expired or not found.'); }
  }
  res.setHeader('Content-Type','application/zip');
  res.setHeader('Content-Disposition','attachment; filename="trancheready-evidence.zip"');
  res.send(entry.zipBuffer);
});

// Errors
app.use((req,res)=>{ res.status(404); try{ return res.render('error',{ title:'Not found', message:'The page you requested was not found.' }); } catch { return res.send('Not Found'); } });
app.use((err,_req,res,_next)=>{ console.error(err); res.status(500); try{ return res.render('error',{ title:'Server error', message:'Please try again shortly.' }); } catch { return res.send('Server error'); } });

const PORT = parseInt(process.env.PORT || '10000', 10);
app.listen(PORT, ()=> console.log('listening on', PORT, 'build', BUILD_ID));
