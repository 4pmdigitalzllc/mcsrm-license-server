// server.js
// ============================================================================
// Multi-Session CRM License Server (Redeem-only)
// - Persistente Mini-DB (Render Disk via DATA_FILE)
// - KEIN Webhook / KEIN Auto-Insert
// - Redeem: Key validieren (optional Lemon API), einmalig konsumieren, Seat anlegen
// - Status / Assign / Release
// - (No-Op) Rebuild
// - Optionales Billing-Portal
// ============================================================================

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

// Node >=18 hat global fetch. Falls nicht, ausnahmsweise nachladen.
let fetchFn = global.fetch;
if (typeof fetchFn !== 'function') {
  try { fetchFn = require('node-fetch'); } catch(_){ /* bleibt undefined */ }
}

const app  = express();
const port = process.env.PORT || 10000;

// ---- Env -------------------------------------------------------------------
// Wenn du Lemon-Validierung willst, setze LEMONSQUEEZY_API_KEY (Test ODER Live).
// Falls leer, läuft die Redeem-Logik rein lokal (Doppelverwendung wird trotzdem verhindert).
const LEMON_KEY     = process.env.LEMONSQUEEZY_API_KEY || '';
const LEMON_VALIDATE= String(process.env.LEMON_VALIDATE || (LEMON_KEY ? 'true' : 'false')).toLowerCase()==='true';

const DATA_FILE     = process.env.DATA_FILE
  ? process.env.DATA_FILE
  : path.join(process.cwd(), 'licenses.json');

const LEMONS_STORE  = (process.env.LEMONS_STORE || '').trim(); // optional für /billing

// ---- Utils -----------------------------------------------------------------
function nowIso(){ return new Date().toISOString(); }
function ensureDirForFile(file){ try{ fs.mkdirSync(path.dirname(file), { recursive:true }); }catch{} }
function safeLC(s){ return String(s||'').trim().toLowerCase(); }
function log(...a){ console.log(...a); }

// ---- Basic CORS (für Aufrufe aus deiner App/Renderer) ----------------------
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

// ---- JSON Parser ------------------------------------------------------------
app.use(express.json());

// ---- Mini-DB (JSON auf persistenter Disk) ----------------------------------
/*
  db = {
    accounts: {
      "owner@email": {
        seats: [{ id, assignedToModelId, assignedToModelName, sourceKey }],
        usedSeats, totalSeats,
        redeemedKeys: { "<keyLC>": { at, byEmail } }
      }
    },
    redeemedGlobal: { "<keyLC>": { at, byEmail } }  // verhindert doppeltes Einlösen account-übergreifend
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
    totalSeats: 0
  };
  if (!Array.isArray(db.accounts[key].seats)) db.accounts[key].seats = [];
  if (!db.accounts[key].redeemedKeys) db.accounts[key].redeemedKeys = {};
  return db.accounts[key];
}
function recalc(acc){
  const seats = acc.seats || [];
  acc.usedSeats  = seats.filter(s => !!s.assignedToModelId).length;
  acc.totalSeats = seats.length;
  return acc;
}

// ---- Lemon API (read-only, optional) ---------------------------------------
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
  if (!LEMON_VALIDATE) return { ok:true }; // Validierung bewusst aus
  const resp = await lemonFetch('license-keys', { 'filter[key]': key });
  const item = Array.isArray(resp?.data) && resp.data[0] ? resp.data[0] : null;
  if (!item) return { ok:false, reason:'not_found' };
  // Optional: Status prüfen (falls benötigt)
  // const status = String(item?.attributes?.status || '').toLowerCase();
  // if (status && status !== 'active') return { ok:false, reason:`status_${status}` };
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
  recalc(acc);

  res.json({
    ok:true,
    email,
    totalSeats: acc.totalSeats,
    usedSeats:  acc.usedSeats,
    seats:      acc.seats
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

  if (acc.seats.find(s=>s.assignedToModelId === modelId)){
    return res.json({ ok:true, msg:'already assigned' });
  }
  const free = acc.seats.find(s=>!s.assignedToModelId);
  if (!free) return res.status(409).json({ ok:false, msg:'no free seat' });

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
  if (!seat) return res.json({ ok:true, msg:'already free' });

  seat.assignedToModelId   = null;
  seat.assignedToModelName = null;

  recalc(acc); saveDb(db);
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

    // 1) global bereits eingelöst?
    if (db.redeemedGlobal && db.redeemedGlobal[key]) {
      const info = db.redeemedGlobal[key];
      return res.status(409).json({ ok:false, error:'key_already_redeemed', by:info.byEmail, at:info.at });
    }
    // 2) im selben Account bereits eingelöst?
    if (acc.redeemedKeys && acc.redeemedKeys[key]) {
      const info = acc.redeemedKeys[key];
      return res.status(409).json({ ok:false, error:'key_already_redeemed_in_account', by:info.byEmail, at:info.at });
    }

    // 3) Optional: gegen Lemon prüfen
    const lr = await findLicenseKeyOnLemon(key);
    if (!lr.ok) {
      return res.status(400).json({ ok:false, error:'invalid_key' });
    }

    // 4) Seat erzeugen (unassigned) & Key markieren
    const seat = {
      id: crypto.randomUUID(),
      assignedToModelId:   null,
      assignedToModelName: null,
      sourceKey: key
    };
    acc.seats.push(seat);

    const meta = { at: nowIso(), byEmail: email };
    acc.redeemedKeys[key]  = meta;
    db.redeemedGlobal[key] = meta;

    recalc(acc); saveDb(db);

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
  res.json({ ok:true, email, totalSeats:acc.totalSeats, usedSeats:acc.usedSeats, seats:acc.seats });
});

// ---- Optional: Billing-Portal (falls du es brauchst) -----------------------
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
