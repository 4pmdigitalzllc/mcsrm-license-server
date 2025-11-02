// server.js
// ============================================================================
// Multi-Session CRM License Server (Express)
// - Persistente Mini-DB (Render Disk via DATA_FILE)
// - Lemon Squeezy Webhook (Seats + Account-Lock)
// - Rebuild-Route (Seats aus Lemon-API rekonstruieren)
// - Status / Assign / Release
// - Billing-Portal Redirect (ohne Portal-API)
// ============================================================================

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const port = process.env.PORT || 10000;

// ---- Env -------------------------------------------------------------------
const SECRET        = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';
const LEMONS_STORE  = (process.env.LEMONS_STORE || '').trim();   // z.B. "4pmdigitalz"
const LEMON_KEY     = process.env.LEMONSQUEEZY_API_KEY || '';
const DATA_FILE     = process.env.DATA_FILE
  ? process.env.DATA_FILE
  : path.join(process.cwd(), 'licenses.json');

// ---- Utils -----------------------------------------------------------------
function nowIso(){ return new Date().toISOString(); }
function ensureDirForFile(file){ try{ fs.mkdirSync(path.dirname(file), { recursive:true }); }catch{} }
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
  try{ ensureDirForFile(DATA_FILE); fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8'); }
  catch(e){ console.error('[DB] write error:', e); }
}
function ensureAcc(db, email){
  const key = String(email||'').toLowerCase();
  if (!db.accounts) db.accounts = {};
  if (!db.accounts[key]) db.accounts[key] = {
    seats: [],
    locked:false,
    lockReason:null
  };
  if (!Array.isArray(db.accounts[key].seats)) db.accounts[key].seats = [];
  return db.accounts[key];
}
function recalc(acc){
  const seats = acc.seats || [];
  acc.usedSeats  = seats.filter(s => !!s.assignedToModelId).length;
  acc.totalSeats = seats.length;
  return acc;
}
function resizeSeatsPreservingAssignments(acc, target){
  const current  = acc.seats || [];
  const assigned = current.filter(s => !!s.assignedToModelId);
  const out = Array.from({ length: target }).map((_, i) => {
    const prev = assigned[i];
    return prev ? { ...prev } : { id: crypto.randomUUID(), assignedToModelId:null, assignedToModelName:null };
  });
  acc.seats = out; recalc(acc);
}

// E-Mail robust aus Webhook-Payload ziehen
function getEmailFromPayload(payload){
  const a = payload?.data?.attributes || {};
  const m = payload?.meta || {};
  const cd = m?.custom_data || {};

  const candidates = [
    a.user_email,             // häufig
    a.customer_email,         // alternative
    a.email,                  // fallback
    cd.email                  // falls im Checkout übergeben
  ].filter(Boolean).map(x => String(x).trim().toLowerCase());

  // gültige E-Mail wählen
  const valid = candidates.find(x => x.includes('@'));
  if (valid) return valid;

  // wenn nur eine “defekte” Variante (ohne '@') existiert, gib sie zurück – Caller kann migrieren
  return candidates[0] || '';
}

function setLockForEmail(email, locked, reason=null){
  const db  = loadDb();
  const acc = ensureAcc(db, email);
  acc.locked = !!locked;
  acc.lockReason = reason ? String(reason) : null;
  saveDb(db);
  console.log(`[Licenses] ${locked?'LOCKED':'UNLOCKED'} ${email} ${reason?'- '+reason:''}`);
}

function migrateSeats(db, fromEmail, toEmail){
  if (!fromEmail || !toEmail || fromEmail===toEmail) return;
  const src = db.accounts?.[fromEmail]; const dst = ensureAcc(db, toEmail);
  if (!src) return;
  // Hänge alle seats von src an dst an (nur freie Ids generieren, keine Überschneidung)
  (src.seats||[]).forEach(s => {
    dst.seats.push({
      id: crypto.randomUUID(),
      assignedToModelId: s.assignedToModelId || null,
      assignedToModelName: s.assignedToModelName || null
    });
  });
  recalc(dst);
  delete db.accounts[fromEmail];
  saveDb(db);
  console.log(`[Migrate] moved ${src.seats?.length||0} seat(s) ${fromEmail} -> ${toEmail}`);
}

// ---- CORS ------------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Headers','content-type, x-signature, x-event-name');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ---- Health ----------------------------------------------------------------
app.get('/',       (_req,res)=>res.status(200).send('OK'));
app.get('/health', (_req,res)=>res.status(200).send('ok'));

// ============================================================================
// ======================  WEBHOOK  ===========================================
// ============================================================================
// Rohkörper NUR hier (HMAC)
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

app.post('/api/lemon/webhook', async (req, res) => {
  try {
    const raw = req.body;                              // Buffer
    const sig = req.get('X-Signature') || '';
    const evh = req.get('X-Event-Name') || '';

    if (!SECRET) { console.log('[Webhook] missing SECRET'); return res.status(500).send('missing secret'); }
    if (!sig)    { console.log('[Webhook] missing signature'); return res.status(400).send('missing signature'); }

    // HMAC prüfen
    const h = crypto.createHmac('sha256', SECRET); h.update(raw);
    const digest = h.digest('hex');
    let ok = false;
    try{ ok = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(digest)); }catch{ ok = false; }
    if (!ok) return res.status(400).send('invalid signature');

    const payload   = JSON.parse(raw.toString('utf8') || '{}');
    const eventName = payload?.meta?.event_name || evh || 'unknown';
    const attr      = payload?.data?.attributes || {};
    const parsed    = getEmailFromPayload(payload);   // robust
    const looksBroken = parsed && !parsed.includes('@');
    const email     = parsed;
    console.log(`[${nowIso()}][Webhook] ${eventName} for ${email||'-'}`);

    const db = loadDb();

    // Falls “kaputter” Key ohne '@': nichts verlieren – buche erst mal dort,
    // versuche aber zusätzlich, Ziel-E-Mail aus anderen Feldern herzuleiten und später zu migrieren.
    let targetEmail = email;
    const alt = (attr.customer_email || attr.user_email || '').toLowerCase();
    const hasAltValid = alt && alt.includes('@');

    // Seats bei order/license events erhöhen
    const addSeats = (qty) => {
      const acc = ensureAcc(db, targetEmail);
      for (let i=0;i<qty;i++){
        acc.seats.push({ id: crypto.randomUUID(), assignedToModelId:null, assignedToModelName:null });
      }
      recalc(acc);
      saveDb(db);
      console.log(`[Webhook] ${eventName} +${qty} seat(s) -> total=${acc.totalSeats} (${targetEmail})`);
    };

    // Bestimme Quantity
    const qtyFromOrder =
      Number(attr?.first_order_item?.quantity ?? 0) ||
      Number(attr?.order_items?.[0]?.quantity ?? 0) ||
      Number(attr?.quantity ?? 0) || 0;

    // Events, die Seats hinzufügen
    if (eventName === 'order_created' || eventName === 'license_key_created') {
      const q = Math.max(1, qtyFromOrder || 1);
      addSeats(q);
    }

    // Lock/Unlock bei Subscriptions
    const badEvents = new Set(['subscription_payment_failed','subscription_expired','subscription_cancelled','subscription_paused']);
    const goodEvents= new Set(['subscription_payment_success','subscription_resumed','subscription_updated','subscription_renewed','subscription_created']);

    if (email) {
      if (badEvents.has(eventName)) {
        setLockForEmail(email, true, eventName);
      } else if (goodEvents.has(eventName)) {
        const status = String(attr?.status || '').toLowerCase();
        if (!status || status==='active' || status==='on_trial') setLockForEmail(email, false, null);
      }
    }

    // Wenn wir eine valide Alt-E-Mail sehen und die aktuelle E-Mail “kaputt” ist:
    // Seats migrieren (damit zukünftige Status-Abfragen mit richtiger E-Mail funktionieren)
    if (looksBroken && hasAltValid) {
      migrateSeats(db, email, alt);
      // und für Rebuild nutzen wir gleich die valide
      targetEmail = alt;
    }

    // Sicherheitsnetz: aus Lemon neu aufbauen
    try{ await rebuildSeatsFromLemon(targetEmail); }catch(e){ console.warn('[Webhook] rebuild skip:', e?.message||e); }

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// ============================================================================
// ========  ab hier normaler JSON-Parser & API  ==============================
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
      // total_quantity oder quantity – je nach Objekt
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
async function rebuildSeatsFromLemon(email){
  const key = String(email||'').toLowerCase();
  if (!key) throw new Error('email required');

  const fromOrders = await getSeatsFromOrders(key);
  const fromSubs   = await getSeatsFromSubscriptions(key);
  const shouldTotal= (Number(fromOrders)||0) + (Number(fromSubs)||0);

  const db  = loadDb();
  const acc = ensureAcc(db, key);

  if (shouldTotal < 0) { recalc(acc); return acc; }
  resizeSeatsPreservingAssignments(acc, shouldTotal);
  saveDb(db);
  console.log(`[Rebuild] ${key} -> totalSeats=${acc.totalSeats}, used=${acc.usedSeats}`);
  return acc;
}

// ---- LICENSE STATUS --------------------------------------------------------
app.get('/api/licenses/status', (req, res)=>{
  const email = String(req.query.email||'').trim().toLowerCase();
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });

  const db  = loadDb();
  const acc = ensureAcc(db, email); recalc(acc);

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

// ---- REBUILD API -----------------------------------------------------------
app.get('/api/licenses/rebuild', async (req, res)=>{
  try{
    const email = String(req.query.email||'').toLowerCase();
    if (!email || !email.includes('@')) return res.status(400).json({ ok:false, error:'email required' });
    const acc = await rebuildSeatsFromLemon(email);
    res.json({ ok:true, email, totalSeats: acc.totalSeats, usedSeats: acc.usedSeats, seats: acc.seats });
  }catch(e){
    console.error('[Rebuild] error', e);
    res.status(500).json({ ok:false, error:'rebuild_failed' });
  }
});

// ============================================================================
// =======  BILLING-PORTAL (Manage Licenses) — ohne Portal-API ================
function createPortalSession(email) {
  if (!LEMONS_STORE) return { ok:false, msg:'LEMONS_STORE missing' };
  const base = `https://${LEMONS_STORE}.lemonsqueezy.com/billing`;
  const url  = email ? `${base}?email=${encodeURIComponent(email)}` : base;
  return { ok:true, url };
}
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

// ---- Debug -----------------------------------------------------------------
app.get('/api/licenses/debug', (_req,res)=>{
  try{ res.json(loadDb()); }catch{ res.json({}); }
});

app.listen(port, () => {
  console.log(`License server listening on ${port}`);
});
