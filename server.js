// server.js
const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

// Optional: node-fetch für Node < 18
let fetchFn = global.fetch;
try {
  if (!fetchFn) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    fetchFn = require('node-fetch');
  }
} catch (_) {
  // Wenn node-fetch nicht installiert ist und Node < 18 läuft, bitte:
  // npm i node-fetch@2
}

const app  = express();
const port = process.env.PORT || 10000;

const SECRET  = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';
const LS_KEY  = process.env.LEMONSQUEEZY_API_KEY || '';

const DATA_FILE = path.join(process.cwd(), 'licenses.json');

// --- CORS (einfach)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, x-signature, x-event-name');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// --- Health
app.get('/',       (req, res) => res.status(200).send('OK'));
app.get('/health', (req, res) => res.status(200).send('ok'));

// -------- helpers: mini „DB“ auf Datei-Basis --------
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

// -------- Webhook braucht RAW-Body vor express.json() --------
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

app.post('/api/lemon/webhook', (req, res) => {
  try {
    const raw   = req.body; // Buffer
    const lsSig = req.get('X-Signature') || req.get('x-signature') || '';
    const eventHdr = req.get('X-Event-Name') || req.get('x-event-name') || '';
    console.log('[Webhook] hit. hdrEvent=', eventHdr, 'len=', raw?.length||0);

    if (!SECRET) { console.log('[Webhook] missing SECRET'); return res.status(500).send('missing secret'); }
    if (!lsSig)  { console.log('[Webhook] missing signature'); return res.status(400).send('missing signature'); }

    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');

    const valid = crypto.timingSafeEqual(Buffer.from(lsSig), Buffer.from(digest));
    console.log('[Webhook] signature valid?', valid);
    if (!valid) return res.status(400).send('invalid signature');

    let payload = {};
    try{ payload = JSON.parse(raw.toString('utf8')); }catch(e){ console.error('[Webhook] JSON parse error:', e); }
    const eventName = payload?.meta?.event_name || eventHdr || 'unknown';
    console.log('[Webhook] payload.meta.event_name:', eventName);

    // MVP: order_created -> Seats um „quantity“ erhöhen
    if (eventName === 'order_created') {
      const emailRaw = payload?.data?.attributes?.user_email;
      const qty      = Number(payload?.data?.attributes?.first_order_item?.quantity || 1);
      const email    = String(emailRaw||'').toLowerCase();

      if (email && qty > 0){
        const db = loadDb();
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

    // Weitere Events (subscription_* etc.) können später ergänzt werden.
    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// --- AB HIER normaler JSON-Parser für alle anderen Routen
app.use(express.json());

// -------- Simple License-API: status / assign / release --------

// GET /api/licenses/status?email=...
app.get('/api/licenses/status', (req, res)=>{
  const email = String(req.query.email||'').trim().toLowerCase();
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });

  const db = loadDb();
  const acc = db.accounts?.[email] || { seats: [] };
  const seats = acc.seats || [];
  const used = seats.filter(s=>!!s.assignedToModelId).length;

  res.json({
    ok:true,
    email,
    totalSeats: seats.length,
    usedSeats: used,
    seats
  });
});

// POST /api/licenses/assign  { email, modelId, modelName }
app.post('/api/licenses/assign', (req, res)=>{
  const email = String(req.body?.email||'').toLowerCase();
  const modelId   = req.body?.modelId;
  const modelName = req.body?.modelName;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db = loadDb();
  const acc = ensureAcc(db, email);
  const seats = acc.seats || [];

  if (seats.find(s=>s.assignedToModelId === modelId)){
    return res.json({ ok:true, msg:'already assigned' });
  }
  const free = seats.find(s=>!s.assignedToModelId);
  if (!free) return res.status(409).json({ ok:false, msg:'no free seat' });

  free.assignedToModelId = modelId;
  free.assignedToModelName = modelName||null;

  saveDb(db);
  res.json({ ok:true, seatId: free.id });
});

// POST /api/licenses/release  { email, modelId }
app.post('/api/licenses/release', (req, res)=>{
  const email = String(req.body?.email||'').toLowerCase();
  const modelId = req.body?.modelId;
  if (!email || !email.includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db = loadDb();
  const acc = ensureAcc(db, email);
  const seats = acc.seats || [];

  const seat = seats.find(s=>s.assignedToModelId === modelId);
  if (!seat) return res.json({ ok:true, msg:'already free' });

  seat.assignedToModelId = null;
  seat.assignedToModelName = null;

  saveDb(db);
  res.json({ ok:true });
});

// -------- Customer-Portal: Manage Billing (LemonSqueezy) --------
// POST /api/licenses/portal  { email }
app.post('/api/licenses/portal', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return res.status(400).json({ ok: false, msg: 'email missing' });
  }
  if (!LS_KEY) {
    return res.status(500).json({ ok:false, msg:'LEMONSQUEEZY_API_KEY missing on server' });
  }

  try {
    const resp = await fetchFn('https://api.lemonsqueezy.com/v1/billing-portal', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LS_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        data: {
          type: 'billing-portals',
          attributes: { email }
        }
      })
    });

    const data = await resp.json();

    if (!resp.ok) {
      console.error('[Portal] Lemon API error:', data);
      return res.status(500).json({ ok: false, msg: 'Lemon API error', data });
    }

    const url = data?.data?.attributes?.url;
    if (!url) {
      console.error('[Portal] missing url:', data);
      return res.status(500).json({ ok: false, msg: 'portal url missing', data });
    }

    return res.json({ ok: true, url });
  } catch (e) {
    console.error('[Portal] server error:', e);
    return res.status(500).json({ ok: false, msg: 'server error' });
  }
});

// --- optional debug
app.get('/api/licenses/debug', (req,res)=>{
  try{ res.json(loadDb()); }catch{ res.json({}); }
});

// --- start
app.listen(port, () => {
  console.log(`License server listening on ${port}`);
});
