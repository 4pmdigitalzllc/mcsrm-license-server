// server.js
// ============================================================================
// Multi-Session CRM License Server (Express)
// - Lemon Squeezy Webhook (Seats-Verwaltung + Account-Lock bei Payment-Issues)
// - Lizenz-Status / Assign / Release
// - Billing-Portal Endpunkte (JSON + Redirect) ohne Lemon-API
// ============================================================================

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

// -------- kleine Utils -------------------------------------------------------
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
const SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || ''; // Webhook-Signatur
const LEMONS_STORE = (process.env.LEMONS_STORE || '').trim(); // z.B. "4pmdigitalz"

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
  return { accounts:{} };
}
function saveDb(db){
  try{
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8');
  }catch(e){ console.error('[DB] write error:', e); }
}
function ensureAcc(db, email){
  const key = String(email||'').toLowerCase();
  if (!db.accounts) db.accounts = {};
  if (!db.accounts[key]) db.accounts[key] = { seats: [], locked:false, lockReason:null };
  if (typeof db.accounts[key].locked !== 'boolean') db.accounts[key].locked = false;
  if (!('lockReason' in db.accounts[key])) db.accounts[key].lockReason = null;
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

    // HMAC prüfen (Längen beachten für timingSafeEqual)
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

    // ==== Seats anlegen bei Erstkauf ====
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

    // ==== Subscription-Events → Lock/Unlock ====
    const emailSub = String(payload?.data?.attributes?.user_email || '').toLowerCase();
    const subStatus = String(payload?.data?.attributes?.status || '').toLowerCase();

    // „schlechte“ Events → lock
    const shouldLock = (
      eventName === 'subscription_payment_failed' ||
      eventName === 'subscription_expired' ||
      eventName === 'subscription_cancelled' ||
      eventName === 'subscription_paused'
    );

    // „gute“ Events → unlock
    const shouldUnlock = (
      eventName === 'subscription_payment_success' ||
      eventName === 'subscription_resumed' ||
      eventName === 'subscription_updated' ||
      eventName === 'subscription_renewed' ||
      eventName === 'subscription_created'
    );

    if (emailSub) {
      if (shouldLock)            setLockForEmail(emailSub, true, eventName);
      else if (shouldUnlock) {
        // Wenn Status bekannt: nur unlocken, wenn wieder aktiv / Trial
        if (!subStatus || subStatus === 'active' || subStatus === 'on_trial') {
          setLockForEmail(emailSub, false, null);
        }
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
// GET /api/licenses/status?email=...
app.get('/api/licenses/status', (req, res)=>{
  const email = String(req.query.email||'').trim().toLowerCase();
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });

  const db    = loadDb();
  const acc   = db.accounts?.[email] || { seats: [], locked:false, lockReason:null };
  const seats = acc.seats || [];
  const used  = seats.filter(s=>!!s.assignedToModelId).length;

  res.json({
    ok:true,
    email,
    totalSeats: seats.length,
    usedSeats: used,
    seats,
    locked: !!acc.locked,
    lockReason: acc.lockReason || null
  });
});

// -------- LICENSE ASSIGN ----------------------------------------------------
// POST /api/licenses/assign  { email, modelId, modelName }
app.post('/api/licenses/assign', (req, res)=>{
  const email     = String(req.body?.email||'').toLowerCase();
  const modelId   = req.body?.modelId;
  const modelName = req.body?.modelName;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db    = loadDb();
  const acc   = ensureAcc(db, email);
  if (acc.locked) return res.status(403).json({ ok:false, msg:'account locked' });

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
// POST /api/licenses/release  { email, modelId }
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
  if (!LEMONS_STORE) return { ok: false, msg: 'LEMONS_STORE missing' };
  const base = `https://${LEMONS_STORE}.lemonsqueezy.com/billing`;
  const url  = email ? `${base}?email=${encodeURIComponent(email)}` : base;
  return { ok: true, url };
}

// JSON-Variante (optional, z. B. für Tests)
app.all('/api/licenses/portal', async (req, res) => {
  try {
    if (req.method === 'GET' && String(req.query.debug || '') === '1') {
      return res.json({ ok: true, url: 'https://example.com' });
    }
    const email = String(
      req.method === 'POST' ? req.body?.email : req.query?.email
    ).trim().toLowerCase();

    console.log('[Portal] hit', req.method, email||'-');

    const out = createPortalSession(email);
    if (!out.ok) return res.status(500).json(out);
    return res.json(out);
  } catch (e) {
    console.error('[Portal] route error:', e);
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

// -------- optionales Debug (nur für Tests) ----------------------------------
app.get('/api/licenses/debug', (req,res)=>{
  try{ res.json(loadDb()); }catch{ res.json({}); }
});

// -------- Start --------------------------------------------------------------
app.listen(port, () => {
  console.log(`License server listening on ${port}`);
});
