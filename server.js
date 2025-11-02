// server.js
// ============================================================================
// Multi-Session CRM License Server (Redeem-only + Webhook-Lock + Seat-Enforcement)
// - Persistente Mini-DB (Render Disk via DATA_FILE)
// - Redeem: Key validieren (optional Lemon API), einmalig konsumieren, Seat anlegen
// - Status / Assign / Release / RemoveSeat
// - Webhook: Lock/Unlock (Abo) + Seat paymentActive/revoked + harte Lock-Neuberechnung
// - Billing-Portal Redirect
// ============================================================================

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

// Node >=18: global fetch; fallback:
let fetchFn = global.fetch;
if (typeof fetchFn !== 'function') {
  try { fetchFn = require('node-fetch'); } catch(_){ /* ignore */ }
}

const app  = express();
const port = process.env.PORT || 10000;

// ---- Env -------------------------------------------------------------------
const LEMON_KEY       = process.env.LEMONSQUEEZY_API_KEY || '';
const LEMON_VALIDATE  = String(process.env.LEMON_VALIDATE || (LEMON_KEY ? 'true' : 'false')).toLowerCase()==='true';
const LEMONS_SIGNING_SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';

const DATA_FILE = process.env.DATA_FILE
  ? process.env.DATA_FILE
  : path.join(process.cwd(), 'licenses.json');

const LEMONS_STORE  = (process.env.LEMONS_STORE || '').trim(); // optional für /billing

// ---- Utils -----------------------------------------------------------------
function nowIso(){ return new Date().toISOString(); }
function ensureDirForFile(file){ try{ fs.mkdirSync(path.dirname(file), { recursive:true }); }catch{} }
function safeLC(s){ return String(s||'').trim().toLowerCase(); }
function log(...a){ console.log(...a); }

// ---- Basic CORS ------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Headers','content-type');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ---- Health ----------------------------------------------------------------
app.get('/',       (req,res)=>res.status(200).send('OK'));
app.get('/health', (req,res)=>res.status(200).send('ok'));

// ---- JSON Parser (für alle außer Webhook) ----------------------------------
app.use(express.json());

// ---- Mini-DB ---------------------------------------------------------------
/*
db = {
  accounts: {
    "owner@email": {
      seats: [{
        id, assignedToModelId, assignedToModelName,
        sourceKey, paymentActive:true|false, revoked:true|false
      }],
      usedSeats, totalSeats,
      redeemedKeys: { "<keyLC>": { at, byEmail } },
      locked:false, lockReason:null
    }
  },
  redeemedGlobal: { "<keyLC>": { at, byEmail } }
}
*/
function loadDb(){
  try{
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const db  = JSON.parse(raw || '{}');
      if (!db.accounts) db.accounts = {};
      if (!db.redeemedGlobal) db.redeemedGlobal = {};
      return db;
    }
  }catch(e){ console.error('[DB] read error:', e); }
  return { accounts:{}, redeemedGlobal:{} };
}
function saveDb(db){
  try{
    ensureDirForFile(DATA_FILE);
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8');
  }catch(e){ console.error('[DB] write error:', e); }
}
function ensureAcc(db, email){
  const key = safeLC(email);
  if (!db.accounts[key]) db.accounts[key] = {
    seats: [],
    redeemedKeys: {},
    usedSeats: 0,
    totalSeats: 0,
    locked: false,
    lockReason: null
  };
  const acc = db.accounts[key];
  if (!Array.isArray(acc.seats)) acc.seats = [];
  if (!acc.redeemedKeys) acc.redeemedKeys = {};
  if (typeof acc.locked !== 'boolean') acc.locked = false;
  if (!('lockReason' in acc)) acc.lockReason = null;
  return acc;
}
function recalc(acc){
  const seats = acc.seats || [];
  acc.usedSeats  = seats.filter(s => !!s.assignedToModelId).length;
  acc.totalSeats = seats.length;
  return acc;
}
function hasAnyUnpaid(acc){
  return (acc?.seats||[]).some(s => s?.paymentActive === false);
}
function enforceLockForAccount(acc){
  const anyUnpaid = hasAnyUnpaid(acc);
  if (anyUnpaid) {
    acc.locked = true;
    if (!acc.lockReason || acc.lockReason === 'subscription_event_unlock') {
      acc.lockReason = 'seat_unpaid';
    }
  } else {
    if (acc.locked && (acc.lockReason === 'seat_unpaid' || !acc.lockReason)) {
      // Entsperre nur, wenn der Lock durch unpaid verursacht war
      acc.locked = false;
      acc.lockReason = null;
    }
  }
}
function setLockForEmail(email, locked, reason=null){
  const db  = loadDb();
  const acc = ensureAcc(db, email);
  acc.locked = !!locked;
  acc.lockReason = reason ? String(reason) : (locked ? 'forced_lock' : null);
  // Nach externer Lock-Entscheidung trotzdem unpaid prüfen
  enforceLockForAccount(acc);
  saveDb(db);
  log(`[Licenses] ${locked?'LOCKED':'UNLOCKED'} ${email} ${reason?'- '+reason:''}`);
}

// ---- Lemon API (optional) --------------------------------------------------
async function lemonFetch(v1Path, params = {}){
  if (!LEMON_VALIDATE || !LEMON_KEY || !fetchFn) return { ok:false, status:0, data:[] };
  const url = new URL(`https://api.lemonsqueezy.com/v1/${v1Path}`);
  Object.entries(params||{}).forEach(([k,v])=> url.searchParams.set(k, String(v)));
  const r = await fetchFn(url, { headers:{
    Authorization: `Bearer ${LEMON_KEY}`,
    Accept: 'application/vnd.api+json'
  }});
  if (!r.ok) {
    const txt = await r.text().catch(()=> '');
    console.warn(`[Lemon API] ${v1Path} returned ${r.status} – body: ${txt}`);
    return { ok:false, status:r.status, data:[] };
  }
  const j = await r.json();
  return { ok:true, status:200, ...j };
}
async function findLicenseKeyOnLemon(key){
  if (!LEMON_VALIDATE) return { ok:true };
  const resp = await lemonFetch('license-keys', { 'filter[key]': key });
  const item = Array.isArray(resp?.data) && resp.data[0] ? resp.data[0] : null;
  if (!item) return { ok:false, reason:'not_found' };
  return { ok:true, item };
}

// ============================================================================
// ============================  API  =========================================
// ============================================================================

// ---- LICENSE STATUS --------------------------------------------------------
app.get('/api/licenses/status', (req, res)=>{
  const email = safeLC(req.query.email);
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });

  const db  = loadDb();
  const acc = ensureAcc(db, email);
  // Erzwinge Lock, falls Seats unpaid (auch ohne Webhook)
  enforceLockForAccount(acc);
  recalc(acc);
  saveDb(db);

  res.json({
    ok:true,
    email,
    totalSeats: acc.totalSeats,
    usedSeats:  acc.usedSeats,
    seats:      acc.seats.map(s=>({
      id: s.id,
      assignedToModelId: s.assignedToModelId || null,
      assignedToModelName: s.assignedToModelName || null,
      paymentActive: (typeof s.paymentActive === 'boolean') ? s.paymentActive : true,
      revoked: !!s.revoked
    })),
    locked:     !!acc.locked,
    lockReason: acc.lockReason || null
  });
});

// ---- LICENSE ASSIGN --------------------------------------------------------
app.post('/api/licenses/assign', (req, res)=>{
  const email     = safeLC(req.body?.email);
  const modelId   = req.body?.modelId;
  const modelName = req.body?.modelName;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db  = loadDb();
  const acc = ensureAcc(db, email);

  // Harte Sperre: unpaid oder explizit locked
  enforceLockForAccount(acc);
  if (acc.locked) { saveDb(db); return res.status(403).json({ ok:false, msg:'account_locked' }); }

  if (acc.seats.find(s=>s.assignedToModelId === modelId)){
    recalc(acc); saveDb(db);
    return res.json({ ok:true, msg:'already assigned' });
  }
  const free = acc.seats.find(s=>!s.assignedToModelId && (s.revoked!==true) && (s.paymentActive!==false));
  if (!free) { recalc(acc); saveDb(db); return res.status(409).json({ ok:false, msg:'no free seat' }); }

  free.assignedToModelId   = modelId;
  free.assignedToModelName = modelName || null;

  recalc(acc); saveDb(db);
  res.json({ ok:true, seatId: free.id });
});

// ---- LICENSE RELEASE --------------------------------------------------------
app.post('/api/licenses/release', (req, res)=>{
  const email   = safeLC(req.body?.email);
  const modelId = req.body?.modelId;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db  = loadDb();
  const acc = ensureAcc(db, email);

  const seat = acc.seats.find(s=>s.assignedToModelId === modelId);
  if (!seat) { recalc(acc); saveDb(db); return res.json({ ok:true, msg:'already free' }); }

  seat.assignedToModelId   = null;
  seat.assignedToModelName = null;

  recalc(acc); saveDb(db);
  res.json({ ok:true });
});

// ---- LICENSE REMOVE SEAT (manuell löschen) ---------------------------------
app.post('/api/licenses/remove_seat', (req, res)=>{
  const email = safeLC(req.body?.email);
  const seatId= String(req.body?.seatId||'');
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!seatId) return res.status(400).json({ ok:false, msg:'seatId missing' });

  const db  = loadDb();
  const acc = ensureAcc(db, email);

  const idx = acc.seats.findIndex(s=>String(s.id)===seatId);
  if (idx<0) return res.status(404).json({ ok:false, msg:'seat_not_found' });

  acc.seats.splice(idx,1);

  recalc(acc);
  enforceLockForAccount(acc);
  saveDb(db);
  res.json({ ok:true });
});

// ---- LICENSE REDEEM (Key einlösen) ----------------------------------------
app.post('/api/licenses/redeem', async (req, res)=>{
  try{
    const email = safeLC(req.body?.email);
    const key   = safeLC(req.body?.licenseKey);
    if (!email || !email.includes('@')) return res.status(400).json({ ok:false, error:'email_missing' });
    if (!key) return res.status(400).json({ ok:false, error:'key_missing' });

    const db  = loadDb();
    const acc = ensureAcc(db, email);

    // Harte Sperre: unpaid Seats blockieren Redeem
    enforceLockForAccount(acc);
    if (acc.locked) { saveDb(db); return res.status(403).json({ ok:false, error:'account_locked' }); }

    if (db.redeemedGlobal && db.redeemedGlobal[key]) {
      const info = db.redeemedGlobal[key];
      return res.status(409).json({ ok:false, error:'key_already_redeemed', by:info.byEmail, at:info.at });
    }
    if (acc.redeemedKeys && acc.redeemedKeys[key]) {
      const info = acc.redeemedKeys[key];
      return res.status(409).json({ ok:false, error:'key_already_redeemed_in_account', by:info.byEmail, at:info.at });
    }

    const lr = await findLicenseKeyOnLemon(key);
    if (!lr.ok) {
      return res.status(400).json({ ok:false, error:'invalid_key' });
    }

    const seat = {
      id: crypto.randomUUID(),
      assignedToModelId:   null,
      assignedToModelName: null,
      sourceKey: key,
      paymentActive: true,
      revoked: false
    };
    acc.seats.push(seat);

    const meta = { at: nowIso(), byEmail: email };
    acc.redeemedKeys[key]  = meta;
    db.redeemedGlobal[key] = meta;

    recalc(acc);
    enforceLockForAccount(acc);
    saveDb(db);

    return res.json({ ok:true, seatId: seat.id, totalSeats: acc.totalSeats, usedSeats: acc.usedSeats });
  }catch(e){
    console.error('[redeem] error', e);
    return res.status(500).json({ ok:false, error:'redeem_failed' });
  }
});

// ---- (No-Op) REBUILD -------------------------------------------------------
app.get('/api/licenses/rebuild', async (req, res)=>{
  const email = safeLC(req.query?.email);
  if (!email) return res.status(400).json({ ok:false, error:'email required' });
  const db  = loadDb();
  const acc = ensureAcc(db, email);
  recalc(acc);
  enforceLockForAccount(acc);
  saveDb(db);
  res.json({ ok:true, email, totalSeats:acc.totalSeats, usedSeats:acc.usedSeats, seats:acc.seats, locked:!!acc.locked, lockReason:acc.lockReason||null });
});

// ============================================================================
// =======================  WEBHOOK: Lock / Key-Status  =======================
// ============================================================================
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

app.post('/api/lemon/webhook', (req, res) => {
  try{
    if (!LEMONS_SIGNING_SECRET) { console.warn('[Webhook] missing secret'); return res.status(500).send('missing secret'); }

    const raw = req.body; // Buffer
    const sig = req.get('X-Signature') || req.get('x-signature') || '';

    // HMAC prüfen
    const hmac = crypto.createHmac('sha256', LEMONS_SIGNING_SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');
    let ok = false;
    try{
      const a = Buffer.from(sig);
      const b = Buffer.from(digest);
      ok = (a.length===b.length) && crypto.timingSafeEqual(a,b);
    }catch{ ok=false; }
    if (!ok) return res.status(400).send('invalid signature');

    const payload   = JSON.parse(raw.toString('utf8'));
    const eventName = payload?.meta?.event_name || 'unknown';
    const attr      = payload?.data?.attributes || {};
    const email     = safeLC(attr?.user_email || attr?.email || '');

    const badEvents = new Set([
      'subscription_payment_failed','subscription_expired','subscription_cancelled','subscription_paused','subscription_past_due'
    ]);
    const goodEvents= new Set([
      'subscription_payment_success','subscription_resumed','subscription_updated','subscription_renewed','subscription_created'
    ]);

    const db  = loadDb();
    let acc   = email ? ensureAcc(db, email) : null;

    // 1) Lock/Unlock basierend auf Subscription-Events
    if (email) {
      if (badEvents.has(eventName)) {
        if (!acc) acc = ensureAcc(db, email);
        acc.locked = true;
        acc.lockReason = eventName;
      } else if (goodEvents.has(eventName)) {
        if (!acc) acc = ensureAcc(db, email);
        // nur entsperren, wenn später keine unpaid Seats mehr bestehen
        acc.lockReason = 'subscription_event_unlock';
        // unlock erfolgt nach enforceLockForAccount()
      }
    }

    // 2) Key/Seat-Status aus Events übernehmen (falls vorhanden)
    const keyFromPayload =
      safeLC(payload?.data?.attributes?.key) ||
      safeLC(payload?.included?.find?.(x=>x?.type==='license-keys')?.attributes?.key || '');

    if (acc && keyFromPayload) {
      const seat = acc.seats.find(s => safeLC(s.sourceKey) === keyFromPayload);
      if (seat) {
        if (eventName === 'license_key_deleted' || eventName === 'license_key_disabled' || eventName === 'order_refunded') {
          seat.paymentActive = false;
          seat.revoked = true;
        }
        if (eventName === 'license_key_updated') {
          const kStatus = String(attr?.status||'').toLowerCase();
          if (kStatus==='enabled' || kStatus==='active') { seat.paymentActive = true; seat.revoked = false; }
          if (kStatus==='disabled' || kStatus==='revoked') { seat.paymentActive = false; seat.revoked = true; }
        }
      }
    }

    // 3) Harte Lock-Neuberechnung (Seats unpaid => lock)
    if (acc) {
      recalc(acc);
      enforceLockForAccount(acc);
    }
    saveDb(db);

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// ============================================================================
// =======  BILLING-PORTAL (Manage Licenses / Billing) ========================
function createPortalSession(email) {
  if (!LEMONS_STORE) return { ok:false, msg:'LEMONS_STORE missing' };
  const base = `https://${LEMONS_STORE}.lemonsqueezy.com/billing`;
  const url  = email ? `${base}?email=${encodeURIComponent(email)}` : base;
  return { ok:true, url };
}
app.all('/api/licenses/portal', (req, res) => {
  try {
    const email = safeLC(req.method === 'POST' ? req.body?.email : req.query?.email);
    const out = createPortalSession(email);
    if (!out.ok) return res.status(500).json(out);
    return res.json(out);
  } catch (e) {
    console.error('[Portal] route error:', e);
    return res.status(500).json({ ok:false, msg:'route error' });
  }
});
app.get('/api/billing/portal', (req, res) => {
  const email = safeLC(req.query?.email);
  const out = createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});
app.post('/api/billing/portal', (req, res) => {
  const email = safeLC(req.body?.email);
  const out = createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});

// ---- Debug -----------------------------------------------------------------
app.get('/api/licenses/debug', (req,res)=>{
  try{ res.json(loadDb()); }catch{ res.json({}); }
});

// ---- Start -----------------------------------------------------------------
app.listen(port, () => {
  console.log(`License server listening on ${port}`);
});
