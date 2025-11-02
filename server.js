// server.js
// ============================================================================
// Multi-Session CRM License Server (Express) – MANUAL REDEEM EDITION
// - Persistente Mini-DB (Render Disk via DATA_FILE)
// - Lemon Squeezy Webhook NUR für Lock/Unlock (KEIN Seat-Autopush)
// - Redeem-Flow: /api/licenses/redeem validiert Key (optional via Lemon API) & erstellt Seat
// - Status / Assign / Release
// - Billing-Portal Redirect
// - Idempotenz: gleiche event_id & gleicher Lizenz-Key werden nur einmal verarbeitet
// ============================================================================

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const port = process.env.PORT || 10000;

// ---- Env -------------------------------------------------------------------
const SECRET        = process.env.LEMONSQUEEZY_SIGNING_SECRET || ''; // Webhook HMAC
const LEMONS_STORE  = (process.env.LEMONS_STORE || '').trim();       // z.B. "4pmdigitalz"
const LEMON_KEY     = process.env.LEMONSQUEEZY_API_KEY || '';        // API für (optionale) Validierung
const DATA_FILE     = process.env.DATA_FILE
  ? process.env.DATA_FILE
  : path.join(process.cwd(), 'licenses.json');

// ---- Utils -----------------------------------------------------------------
function nowIso(){ return new Date().toISOString(); }
function safeJsonParse(x){ try{ return JSON.parse(Buffer.isBuffer(x)?x.toString('utf8'):String(x||'{}')); }catch{return {}; } }
function ensureDirForFile(file){ try{ fs.mkdirSync(path.dirname(file), { recursive:true }); }catch{} }
function log(...a){ console.log(...a); }
function uuid(){ return crypto.randomUUID(); }

// ---- CORS (simple) ---------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Headers','content-type, x-signature, x-event-name');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ---- Health ----------------------------------------------------------------
app.get('/',       (req,res)=>res.status(200).send('OK'));
app.get('/health', (req,res)=>res.status(200).send('ok'));

// ---- Mini-DB (JSON-Datei auf persistenter Disk) ----------------------------
/**
 * Schema:
 * {
 *   accounts: {
 *     [email]: {
 *       seats: [{ id, assignedToModelId, assignedToModelName }],
 *       redeemedKeys: [ "ABCD-EFGH-..." ],
 *       processedEvents: [ "evt_..." ],   // idempotency for webhooks
 *       locked: boolean,
 *       lockReason: string|null
 *     }
 *   }
 * }
 */
function loadDb(){
  try{
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const db  = JSON.parse(raw || '{}');
      if (!db.accounts) db.accounts = {};
      return db;
    }
  }catch(e){ console.error('[DB] read error:', e); }
  return { accounts:{} };
}
function saveDb(db){
  try{
    ensureDirForFile(DATA_FILE);
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8');
  }catch(e){ console.error('[DB] write error:', e); }
}
function ensureAcc(db, email){
  const key = String(email||'').toLowerCase();
  if (!db.accounts) db.accounts = {};
  if (!db.accounts[key]) db.accounts[key] = {
    seats: [],
    redeemedKeys: [],
    processedEvents: [],
    locked:false,
    lockReason:null
  };
  const acc = db.accounts[key];
  if (!Array.isArray(acc.seats)) acc.seats = [];
  if (!Array.isArray(acc.redeemedKeys)) acc.redeemedKeys = [];
  if (!Array.isArray(acc.processedEvents)) acc.processedEvents = [];
  if (typeof acc.locked !== 'boolean') acc.locked = false;
  if (!('lockReason' in acc)) acc.lockReason = null;
  recalc(acc);
  return acc;
}
function setLockForEmail(email, locked, reason=null){
  const db  = loadDb();
  const acc = ensureAcc(db, email);
  acc.locked = !!locked;
  acc.lockReason = reason ? String(reason) : null;
  saveDb(db);
  log(`[Licenses] ${locked?'LOCKED':'UNLOCKED'} ${email} ${reason?'- '+reason:''}`);
}
function recalc(acc){
  const seats = acc.seats || [];
  acc.usedSeats  = seats.filter(s => !!s.assignedToModelId).length;
  acc.totalSeats = seats.length;
  return acc;
}

// ============================================================================
// ==============  LEMON SQUEEZY WEBHOOK  =====================================
// ============================================================================
// RAW Body NUR für diese Route (für HMAC-Verifikation)
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

app.post('/api/lemon/webhook', async (req, res) => {
  try {
    const raw      = req.body; // Buffer
    const sig      = req.get('X-Signature') || req.get('x-signature') || '';
    const eventHdr = req.get('X-Event-Name') || req.get('x-event-name') || '';
    if (!SECRET) { console.log('[Webhook] missing SECRET'); return res.status(500).send('missing secret'); }
    if (!sig)    { console.log('[Webhook] missing signature'); return res.status(400).send('missing signature'); }

    // HMAC prüfen
    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');
    let ok = false;
    try{
      const a = Buffer.from(sig);
      const b = Buffer.from(digest);
      ok = (a.length===b.length) && crypto.timingSafeEqual(a,b);
    }catch{ ok=false; }
    if (!ok) return res.status(400).send('invalid signature');

    const payload   = safeJsonParse(raw);
    const eventName = payload?.meta?.event_name || eventHdr || 'unknown';
    const eventId   = payload?.meta?.event_id || payload?.meta?.id || payload?.id || null;

    // Email (für Lock/Unlock relevant)
    const attr      = payload?.data?.attributes || {};
    const email     = String(attr?.user_email || attr?.email || '').toLowerCase();

    console.log(`[${nowIso()}][Webhook] ${eventName} ${eventId||''} for ${email||'-'}`);

    // Ab hier: KEIN Seat-Autopush mehr!
    // -> Wir nutzen Webhooks nur für Lock/Unlock und Idempotenz-Marker.

    if (email) {
      const db  = loadDb();
      const acc = ensureAcc(db, email);

      // Idempotenz der Events
      if (eventId && acc.processedEvents.includes(eventId)) {
        return res.status(200).send('already processed');
      }

      // Lock/Unlock-Logik (wie gehabt)
      const badEvents = new Set(['subscription_payment_failed','subscription_expired','subscription_cancelled','subscription_paused']);
      const goodEvents= new Set(['subscription_payment_success','subscription_resumed','subscription_updated','subscription_renewed','subscription_created']);

      if (badEvents.has(eventName)) {
        acc.locked = true;
        acc.lockReason = eventName;
      } else if (goodEvents.has(eventName)) {
        const status = String(attr?.status || '').toLowerCase();
        if (!status || status==='active' || status==='on_trial') {
          acc.locked = false;
          acc.lockReason = null;
        }
      }

      // Event idempotent markieren & speichern
      if (eventId) acc.processedEvents.push(eventId);
      recalc(acc); saveDb(db);
    }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    // 200 zurückgeben, um Lemon-Retries klein zu halten (wir sind idempotent)
    return res.status(200).send('ok');
  }
});

// ============================================================================
// =========  ab hier normaler JSON-Parser & API  =============================
app.use(express.json());

// ---- Lemon API (nur für optionale Redeem-Validierung / Portal) ------------
async function lemonFetch(v1Path, params = {}){
  if (!LEMON_KEY) throw new Error('LEMONSQUEEZY_API_KEY missing');
  const url = new URL(`https://api.lemonsqueezy.com/v1/${v1Path}`);
  Object.entries(params||{}).forEach(([k,v])=> url.searchParams.set(k, String(v)));
  const r = await fetch(url, { headers:{
    Authorization: `Bearer ${LEMON_KEY}`,
    Accept: 'application/vnd.api+json'
  }});
  if (!r.ok) {
    console.warn(`[Lemon API] ${v1Path} returned ${r.status}`);
    return { data: [] };
  }
  return r.json();
}

/**
 * Optional: Lizenz-Key gegen Lemon prüfen.
 * Versucht, den Key zu finden und Status zu validieren.
 * Falls API-Key nicht gesetzt oder Lemon nichts liefert, entscheiden wir konservativ:
 *  - Kein Treffer => invalid_key
 *  - Treffer => ok
 */
async function validateLicenseKeyWithLemon(licenseKey){
  if (!LEMON_KEY) {
    // Ohne API-Key keine Online-Validierung möglich -> lass es den Client probieren
    return { ok: true, meta: { checked:false } };
  }
  try{
    const data = await lemonFetch('license-keys', { 'filter[key]': licenseKey });
    const list = Array.isArray(data?.data) ? data.data : [];
    if (list.length === 0) return { ok:false, error:'invalid_key' };

    // Du könntest hier weitere Checks machen, z.B. status / deaktiviert etc.
    // const attrs = list[0]?.attributes || {};
    return { ok:true, meta:{ checked:true, count:list.length } };
  }catch(e){
    console.warn('[validateLicenseKeyWithLemon] error:', e?.message||e);
    // Bei Fehler lieber nicht automatisch akzeptieren
    return { ok:false, error:'validation_failed' };
  }
}

// ---- LICENSE REDEEM --------------------------------------------------------
/**
 * POST /api/licenses/redeem
 * body: { email, licenseKey }
 * - Prüft, ob Key schon redeemed wurde (global, nicht nur bei diesem Account)
 * - Optional: validiert Key via Lemon API (wenn LEMON_KEY vorhanden)
 * - Erst bei Erfolg wird ein neuer Seat erstellt
 */
app.post('/api/licenses/redeem', async (req, res) => {
  try {
    const email = String(req.body?.email||'').trim().toLowerCase();
    const licenseKey = String(req.body?.licenseKey||'').trim().toUpperCase();

    if (!email || !email.includes('@')) return res.status(400).json({ ok:false, error:'missing_email' });
    if (!licenseKey) return res.status(400).json({ ok:false, error:'missing_license_key' });

    const db  = loadDb();
    // Globale Dup-Check über alle Accounts
    for (const accEmail of Object.keys(db.accounts||{})) {
      const acc = ensureAcc(db, accEmail);
      if (acc.redeemedKeys.includes(licenseKey)) {
        return res.json({ ok:false, error:'already_redeemed' });
      }
    }

    // Optional: extern validieren
    const val = await validateLicenseKeyWithLemon(licenseKey);
    if (!val.ok) {
      return res.json({ ok:false, error: val.error || 'invalid_key' });
    }

    const acc = ensureAcc(db, email);
    // Nochmals acc-seitig prüfen (idempotenz)
    if (acc.redeemedKeys.includes(licenseKey)) {
      return res.json({ ok:false, error:'already_redeemed' });
    }

    // Seat erzeugen
    const seat = { id: uuid(), assignedToModelId:null, assignedToModelName:null };
    acc.seats.push(seat);
    acc.redeemedKeys.push(licenseKey);
    recalc(acc);
    saveDb(db);

    return res.json({ ok:true, totalSeats: acc.totalSeats, usedSeats: acc.usedSeats, seatId: seat.id });
  } catch (e) {
    console.error('[redeem] error', e);
    return res.status(500).json({ ok:false, error:'server_error' });
  }
});

// ---- LICENSE STATUS --------------------------------------------------------
app.get('/api/licenses/status', (req, res)=>{
  const email = String(req.query.email||'').trim().toLowerCase();
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });

  const db  = loadDb();
  const acc = ensureAcc(db, email);
  recalc(acc);

  res.json({
    ok:true,
    email,
    totalSeats: acc.totalSeats,
    usedSeats:  acc.usedSeats,
    seats:      acc.seats,
    // Nur Info: wie viele Keys wurden eingelöst (== totalSeats)
    redeemedKeys: acc.redeemedKeys,
    locked:     !!acc.locked,
    lockReason: acc.lockReason || null
  });
});

// ---- LICENSE ASSIGN --------------------------------------------------------
app.post('/api/licenses/assign', (req, res)=>{
  const email     = String(req.body?.email||'').toLowerCase();
  const modelId   = req.body?.modelId;
  const modelName = req.body?.modelName;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db  = loadDb();
  const acc = ensureAcc(db, email);
  if (acc.locked) return res.status(403).json({ ok:false, msg:'account locked' });

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
  const email   = String(req.body?.email||'').toLowerCase();
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

// ---- REBUILD API (No-Op: kein externer Seat-Sync mehr) ---------------------
/**
 * Vorher: Seats anhand Orders/Subs ermittelt (führte zu Auto-Add).
 * Jetzt: Rebuild ist bewusst "no-op" und gibt nur aktuellen lokalen Zustand zurück.
 */
app.get('/api/licenses/rebuild', async (req, res)=>{
  try{
    const email = String(req.query.email||'').toLowerCase();
    if (!email) return res.status(400).json({ ok:false, error:'email required' });
    const db  = loadDb();
    const acc = ensureAcc(db, email);
    recalc(acc);
    res.json({
      ok:true, email,
      totalSeats: acc.totalSeats, usedSeats: acc.usedSeats, seats: acc.seats
    });
  }catch(e){
    console.error('[Rebuild] error', e);
    res.status(500).json({ ok:false, error:'rebuild_failed' });
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

// JSON-Variante (optional)
app.all('/api/licenses/portal', async (req, res) => {
  try {
    const email = String(
      req.method === 'POST' ? req.body?.email : req.query?.email
    ).trim().toLowerCase();
    const out = createPortalSession(email);
    if (!out.ok) return res.status(500).json(out);
    return res.json(out);
  } catch (e) {
    console.error('[Portal] route error:', e);
    return res.status(500).json({ ok:false, msg:'route error' });
  }
});

// Redirect-Endpunkte für window.open()
app.get('/api/billing/portal', (req, res) => {
  const email = String(req.query.email||'').trim().toLowerCase();
  const out = createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});
app.post('/api/billing/portal', (req, res) => {
  const email = String(req.body?.email||'').trim().toLowerCase();
  const out = createPortalSession(email);
  if (!out.ok) return res.status(500).json(out);
  return res.redirect(302, out.url);
});

// ---- Debug (nur dev) -------------------------------------------------------
app.get('/api/licenses/debug', (req,res)=>{
  try{ res.json(loadDb()); }catch{ res.json({}); }
});

// ---- Start -----------------------------------------------------------------
app.listen(port, () => {
  console.log(`License server listening on ${port}`);
});
