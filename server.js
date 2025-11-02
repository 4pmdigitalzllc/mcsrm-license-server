// server.js
// ============================================================================
// Multi-Session CRM License Server (Express)
// - Persistente Mini-DB (Render Disk via DATA_FILE)
// - Lemon Squeezy Webhook (Seats + Account-Lock)
// - Rebuild-Route (Seats aus Lemon-API rekonstruieren)
// - Status / Assign / Release
// - Billing-Portal Redirect (ohne Lemon-Portal-API)
// ============================================================================

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

// ----------------------------------------------------------------------------
const app  = express();
const port = process.env.PORT || 10000;

// ---- Env -------------------------------------------------------------------
const SECRET        = process.env.LEMONSQUEEZY_SIGNING_SECRET || ''; // Webhook HMAC
const LEMONS_STORE  = (process.env.LEMONS_STORE || '').trim();       // z.B. "4pmdigitalz"
const LEMON_KEY     = process.env.LEMONSQUEEZY_API_KEY || '';        // API für Rebuild
const DATA_FILE     = process.env.DATA_FILE
  ? process.env.DATA_FILE
  : path.join(process.cwd(), 'licenses.json');

// ---- Utils -----------------------------------------------------------------
function nowIso(){ return new Date().toISOString(); }
function safeJsonParse(x){ try{ return JSON.parse(Buffer.isBuffer(x)?x.toString('utf8'):String(x||'{}')); }catch{return {}; } }
function ensureDirForFile(file){ try{ fs.mkdirSync(path.dirname(file), { recursive:true }); }catch{} }

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
    seats: [],                 // [{ id, assignedToModelId, assignedToModelName }]
    locked:false,
    lockReason:null
  };
  if (typeof db.accounts[key].locked !== 'boolean') db.accounts[key].locked = false;
  if (!('lockReason' in db.accounts[key])) db.accounts[key].lockReason = null;
  if (!Array.isArray(db.accounts[key].seats)) db.accounts[key].seats = [];
  return db.accounts[key];
}
function setLockForEmail(email, locked, reason=null){
  const db  = loadDb();
  const acc = ensureAcc(db, email);
  acc.locked = !!locked;
  acc.lockReason = reason ? String(reason) : null;
  saveDb(db);
  console.log(`[Licenses] ${locked?'LOCKED':'UNLOCKED'} ${email} ${reason?'- '+reason:''}`);
}
function recalc(acc){
  const seats = acc.seats || [];
  acc.usedSeats  = seats.filter(s => !!s.assignedToModelId).length;
  acc.totalSeats = seats.length;
  return acc;
}
function resizeSeatsPreservingAssignments(acc, target){
  const current = acc.seats || [];
  const assigned = current.filter(s => !!s.assignedToModelId);
  const newSeats = Array.from({ length: target }).map((_, i) => {
    const prev = assigned[i];
    return prev ? { ...prev } : { id: crypto.randomUUID(), assignedToModelId:null, assignedToModelName:null };
  });
  acc.seats = newSeats;
  recalc(acc);
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
    const attr      = payload?.data?.attributes || {};
    const email     = String(attr?.user_email || '').toLowerCase();

    console.log(`[${nowIso()}][Webhook] ${eventName} for ${email||'-'}`);

    // Seats hinzufügen bei einmaligen Orders (order_created)
    if (eventName === 'order_created') {
      const qty = Number(attr?.first_order_item?.quantity || 1);
      if (email && qty > 0){
        const db  = loadDb();
        const acc = ensureAcc(db, email);
        for (let i=0;i<qty;i++){
          acc.seats.push({ id: crypto.randomUUID(), assignedToModelId:null, assignedToModelName:null });
        }
        recalc(acc); saveDb(db);
        console.log(`[Webhook] order_created +${qty} seat(s) -> total=${acc.totalSeats}`);
      }
    }

    // Lock/Unlock nach Sub-Status
    const badEvents = new Set(['subscription_payment_failed','subscription_expired','subscription_cancelled','subscription_paused']);
    const goodEvents= new Set(['subscription_payment_success','subscription_resumed','subscription_updated','subscription_renewed','subscription_created']);

    if (email) {
      if (badEvents.has(eventName)) {
        setLockForEmail(email, true, eventName);
      } else if (goodEvents.has(eventName)) {
        // nur unlocken, wenn status aktiv/trial oder Status fehlt
        const status = String(attr?.status || '').toLowerCase();
        if (!status || status==='active' || status==='on_trial') setLockForEmail(email, false, null);
      }

      // Sicherheitsnetz: Bei Sub-Events (good/bad) Seats aus Lemon neu spiegeln
      try{ await rebuildSeatsFromLemon(email); }catch(e){ console.warn('[Webhook] rebuild skip:', e?.message||e); }
    }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// ============================================================================
// =========  ab hier normaler JSON-Parser & API  =============================
app.use(express.json());

// ---- Lemon API (read-only) für Rebuild -------------------------------------
async function lemonFetch(v1Path, params = {}){
  if (!LEMON_KEY) throw new Error('LEMONSQUEEZY_API_KEY missing');
  const url = new URL(`https://api.lemonsqueezy.com/v1/${v1Path}`);
  Object.entries(params||{}).forEach(([k,v])=> url.searchParams.set(k, String(v)));
  const r = await fetch(url, { headers:{
    Authorization: `Bearer ${LEMON_KEY}`,
    Accept: 'application/vnd.api+json'
  }});
  if (!r.ok) throw new Error(`Lemon ${v1Path} ${r.status}`);
  return r.json();
}
async function getSeatsFromOrders(email){
  try{
    const data = await lemonFetch('orders', { 'filter[customer_email]': email });
    const list = Array.isArray(data?.data) ? data.data : [];
    return list.reduce((sum, o)=>{
      const q = o?.attributes?.total_quantity ?? o?.attributes?.quantity ?? 0;
      return sum + (Number(q)||0);
    }, 0);
  }catch{ return 0; }
}
async function getSeatsFromSubscriptions(email){
  try{
    const data = await lemonFetch('subscriptions', {
      'filter[customer_email]': email,
      'filter[status]': 'active'
    });
    const list = Array.isArray(data?.data) ? data.data : [];
    return list.reduce((sum, s)=>{
      const q = s?.attributes?.quantity ?? s?.attributes?.variant_quantity ?? 1;
      return sum + (Number(q)||0);
    }, 0);
  }catch{ return 0; }
}
/** Baut Seats aus Lemon neu auf (erhält vorhandene Assignments soweit möglich) */
async function rebuildSeatsFromLemon(email){
  const key = String(email||'').toLowerCase();
  if (!key) throw new Error('email required');
  const shouldTotal = (await getSeatsFromOrders(key)) + (await getSeatsFromSubscriptions(key));

  const db  = loadDb();
  const acc = ensureAcc(db, key);
  if (shouldTotal < 0) return recalc(acc);

  resizeSeatsPreservingAssignments(acc, shouldTotal);
  saveDb(db);
  console.log(`[Rebuild] ${key} -> totalSeats=${acc.totalSeats}, used=${acc.usedSeats}`);
  return acc;
}

// ---- LICENSE STATUS --------------------------------------------------------
// GET /api/licenses/status?email=...
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
    locked:     !!acc.locked,
    lockReason: acc.lockReason || null
  });
});

// ---- LICENSE ASSIGN --------------------------------------------------------
// POST /api/licenses/assign  { email, modelId, modelName }
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

// ---- LICENSE RELEASE -------------------------------------------------------
// POST /api/licenses/release  { email, modelId }
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

// ---- REBUILD API (Recovery / Sync) ----------------------------------------
// GET /api/licenses/rebuild?email=...
app.get('/api/licenses/rebuild', async (req, res)=>{
  try{
    const email = String(req.query.email||'').toLowerCase();
    if (!email) return res.status(400).json({ ok:false, error:'email required' });
    const acc = await rebuildSeatsFromLemon(email);
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
// =======  BILLING-PORTAL (Manage Licenses / Billing) — ohne Portal-API ======
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
