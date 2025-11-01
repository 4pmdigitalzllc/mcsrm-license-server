// server.js
// ============================================================================
// Multi-Session CRM License Server (Express)
// - Lemon Squeezy Webhook (Seats-Verwaltung)
// - Lizenz-Status / Assign / Release
// - Billing-Portal Endpunkte (JSON + Redirect) mit Timeout & Debug
// ============================================================================

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

// -------- fetch helper (Node < 18 Kompatibilität) ---------------------------
let fetchFn = global.fetch;
if (!fetchFn) {
  try {
    const nf = require('node-fetch');           // v2/v3 kompatibel
    fetchFn = nf.default || nf;
  } catch (e) {
    console.warn('[Init] node-fetch nicht gefunden. Installiere ggf.: npm i node-fetch@2');
  }
}

// -------- kleine Utils -------------------------------------------------------
const sleep = (ms)=> new Promise(r=>setTimeout(r, ms));

function safeJsonParse(bufOrStr){
  try{
    if (Buffer.isBuffer(bufOrStr)) return JSON.parse(bufOrStr.toString('utf8'));
    if (typeof bufOrStr === 'string') return JSON.parse(bufOrStr);
  }catch(e){}
  return {};
}

function nowIso(){ return new Date().toISOString(); }

// ----------------------------------------------------------------------------
const app  = express();
const port = process.env.PORT || 10000;

// ---- Secrets / Keys aus Environment (Render Dashboard) ---------------------
const SECRET  = process.env.LEMONSQUEEZY_SIGNING_SECRET || ''; // Webhook-Signatur
const LS_KEY  = process.env.LEMONSQUEEZY_API_KEY || '';        // Lemon API
const STORE_ID = process.env.LEMON_STORE_ID || '';             // optional

// ---- Mini-DB (Datei) -------------------------------------------------------
const DATA_FILE = path.join(process.cwd(), 'licenses.json');

// -------- CORS (einfach) ----------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, x-signature, x-event-name');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// -------- Health ------------------------------------------------------------
app.get('/',       (req, res) => res.status(200).send('OK'));
app.get('/health', (req, res) => res.status(200).send('ok'));

// -------- Datei-DB Helpers --------------------------------------------------
function loadDb(){
  try{
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      return JSON.parse(raw || '{}');
    }
  }catch(e){ console.error('[DB] read error:', e); }
  return { accounts:{} }; // accounts[email] = { seats: [ {id, assignedToModelId|null, assignedToModelName|null} ] }
}
function saveDb(db){
  try{
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8');
  }catch(e){ console.error('[DB] write error:', e); }
}
function ensureAcc(db, email){
  const key = String(email||'').toLowerCase();
  if (!db.accounts) db.accounts = {};
  if (!db.accounts[key]) db.accounts[key] = { seats: [] };
  return db.accounts[key];
}

// ============================================================================
// ==============  LEMON SQUEEZY WEBHOOK  =====================================
// ============================================================================
// Wichtig: RAW Body vor express.json()
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

app.post('/api/lemon/webhook', (req, res) => {
  try {
    const raw      = req.body; // Buffer
    const lsSig    = req.get('X-Signature') || req.get('x-signature') || '';
    const eventHdr = req.get('X-Event-Name') || req.get('x-event-name') || '';
    console.log(`[${nowIso()}][Webhook] hit. hdrEvent=${eventHdr} len=${raw?.length||0}`);

    if (!SECRET) { console.log('[Webhook] missing SECRET'); return res.status(500).send('missing secret'); }
    if (!lsSig)  { console.log('[Webhook] missing signature'); return res.status(400).send('missing signature'); }

    // HMAC prüfen
    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digestHex = hmac.digest('hex');

    let valid = false;
    try{
      const a = Buffer.from(lsSig);
      const b = Buffer.from(digestHex);
      valid = (a.length === b.length) && crypto.timingSafeEqual(a, b);
    }catch{ valid = false; }

    console.log('[Webhook] signature valid?', valid);
    if (!valid) return res.status(400).send('invalid signature');

    // Payload parsen
    const payload   = safeJsonParse(raw);
    const eventName = payload?.meta?.event_name || eventHdr || 'unknown';
    console.log('[Webhook] payload.meta.event_name:', eventName);

    // MVP: order_created -> Seats um quantity erhöhen
    if (eventName === 'order_created') {
      const emailRaw = payload?.data?.attributes?.user_email;
      const qty      = Number(payload?.data?.attributes?.first_order_item?.quantity || 1);
      const email    = String(emailRaw||'').toLowerCase();

      if (email && qty > 0){
        const db  = loadDb();
        const acc = ensureAcc(db, email);
        for (let i=0;i<qty;i++){
          acc.seats.push({ id: crypto.randomUUID(), assignedToModelId: null, assignedToModelName: null });
        }
        saveDb(db);
        console.log(`[Webhook] Added ${qty} seat(s) for`, email, 'total=', acc.seats.length);
      } else {
        console.log('[Webhook] order_created without email/qty');
      }
    }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// ============================================================================
// =========  ab hier normaler JSON-Parser & API  =============================
// ============================================================================
app.use(express.json());

// -------- LICENSE STATUS ----------------------------------------------------
app.get('/api/licenses/status', (req, res)=>{
  const email = String(req.query.email||'').trim().toLowerCase();
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });

  const db    = loadDb();
  const acc   = db.accounts?.[email] || { seats: [] };
  const seats = acc.seats || [];
  const used  = seats.filter(s=>!!s.assignedToModelId).length;

  res.json({ ok:true, email, totalSeats: seats.length, usedSeats: used, seats });
});

// -------- LICENSE ASSIGN ----------------------------------------------------
app.post('/api/licenses/assign', (req, res)=>{
  const email     = String(req.body?.email||'').toLowerCase();
  const modelId   = req.body?.modelId;
  const modelName = req.body?.modelName;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db    = loadDb();
  const acc   = ensureAcc(db, email);
  const seats = acc.seats || [];

  if (seats.find(s=>s.assignedToModelId === modelId)){
    return res.json({ ok:true, msg:'already assigned' });
  }
  const free = seats.find(s=>!s.assignedToModelId);
  if (!free) return res.status(409).json({ ok:false, msg:'no free seat' });

  free.assignedToModelId   = modelId;
  free.assignedToModelName = modelName || null;

  saveDb(db);
  res.json({ ok:true, seatId: free.id });
});

// -------- LICENSE RELEASE ---------------------------------------------------
app.post('/api/licenses/release', (req, res)=>{
  const email   = String(req.body?.email||'').toLowerCase();
  const modelId = req.body?.modelId;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db    = loadDb();
  const acc   = ensureAcc(db, email);
  const seats = acc.seats || [];

  const seat = seats.find(s=>s.assignedToModelId === modelId);
  if (!seat) return res.json({ ok:true, msg:'already free' });

  seat.assignedToModelId   = null;
  seat.assignedToModelName = null;

  saveDb(db);
  res.json({ ok:true });
});

// ============================================================================
// =======  BILLING-PORTAL (Manage Licenses / Billing) — ohne Lemon-API =======
// ============================================================================

// .env/Render: LEMONS_STORE=4pmdigitalz   (dein Store-Subdomain-Name)
function createPortalSession(email) {
  const store = (process.env.LEMONS_STORE || '').trim(); // z.B. "4pmdigitalz"
  if (!store) return { ok: false, msg: 'LEMONS_STORE missing' };

  const base = `https://${store}.lemonsqueezy.com/billing`;
  const url  = email ? `${base}?email=${encodeURIComponent(email)}` : base;

  return { ok: true, url };
}

// JSON-Variante (falls du sie brauchst)
app.all('/api/licenses/portal', async (req, res) => {
  try {
    if (req.method === 'GET' && String(req.query.debug || '') === '1') {
      return res.json({ ok: true, url: 'https://example.com' });
    }
    const email = String(
      req.method === 'POST' ? req.body?.email : req.query?.email
    ).trim().toLowerCase();

    const out = createPortalSession(email);
    if (!out.ok) return res.status(500).json(out);
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ ok:false, msg:'route error' });
  }
});

// Redirect-Endpoints für window.open()
app.get('/api/billing/portal', async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const out = createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});

app.post('/api/billing/portal', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const out = createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});
/**
 * JSON-API: POST /api/licenses/portal  { email }
 * -> { ok:true, url:"..." }
 * Debug: GET /api/licenses/portal?debug=1
 */
app.all('/api/licenses/portal', async (req, res) => {
  try{
    if (req.method === 'GET' && String(req.query.debug||'') === '1') {
      return res.json({ ok: true, url: 'https://example.com' });
    }
    const email = String(
      req.method === 'POST' ? req.body?.email : req.query?.email
    ).trim().toLowerCase();

    console.log('[Portal] hit', req.method, email||'-');

    const out = await createPortalSession(email);
    if (!out.ok) return res.status(500).json(out);
    return res.json(out);
  }catch(e){
    console.error('[Portal] route error:', e);
    return res.status(500).json({ ok:false, msg:'route error' });
  }
});

/**
 * Kompatible Endpunkte für window.open():
 * GET /api/billing/portal?email=...
 * POST /api/billing/portal { email }
 * -> 302 Redirect direkt ins Lemon-Billing-Portal
 */
app.get('/api/billing/portal', async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const out = await createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});

app.post('/api/billing/portal', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const out = await createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});

// -------- optionales Debug (nur für Tests) ----------------------------------
app.get('/api/licenses/debug', (req,res)=>{
  try{ res.json(loadDb()); }catch{ res.json({}); }
});

// -------- Start --------------------------------------------------------------
app.listen(port, () => {
  console.log(`License server listening on ${port}`);
});
