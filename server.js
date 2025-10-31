// server.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 10000;
const SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';

const DATA_FILE = path.join(process.cwd(), 'licenses.json');

// --- tiny CORS for the Electron app / local dev
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, x-signature, x-event-name');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// --- health / root
app.get('/', (req, res) => res.status(200).send('OK'));
app.get('/health', (req, res) => res.status(200).send('ok'));

// -------- persistence helpers --------
function loadDb(){
  try{
    if(fs.existsSync(DATA_FILE)){
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      return JSON.parse(raw||'{}');
    }
  }catch{}
  return { accounts:{} }; // accounts[email] = { seats: [ {id, assignedToModelId|null, assignedToModelName|null} ] }
}
function saveDb(db){
  try{
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8');
  }catch(e){
    console.error('[DB] write error:', e);
  }
}
function ensureAcc(db, email){
  db.accounts = db.accounts || {};
  db.accounts[email] = db.accounts[email] || { seats: [] };
  return db.accounts[email];
}

// -------- lemon webhook (raw body) --------
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

app.post('/api/lemon/webhook', (req, res) => {
  try {
    const raw = req.body; // Buffer
    const lsSig = req.get('X-Signature') || req.get('x-signature') || '';
    const event = req.get('X-Event-Name') || req.get('x-event-name') || '';
    console.log('[Webhook] hit. event:', event, 'len=', raw?.length||0);

    if (!SECRET) { console.log('[Webhook] missing SECRET'); return res.status(500).send('missing secret'); }
    if (!lsSig)   { console.log('[Webhook] missing signature'); return res.status(400).send('missing signature'); }

    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');

    const valid = crypto.timingSafeEqual(Buffer.from(lsSig), Buffer.from(digest));
    console.log('[Webhook] signature valid?', valid);
    if (!valid) return res.status(400).send('invalid signature');

    const payload = JSON.parse(raw.toString('utf8'));
    const eventName = payload?.meta?.event_name || event || 'unknown';
    console.log('[Webhook] payload.meta.event_name:', eventName);

    // Für MVP: bei "order_created" die Seat-Anzahl um "quantity" erhöhen
    if (eventName === 'order_created') {
      const email = payload?.data?.attributes?.user_email;
      const qty   = Number(payload?.data?.attributes?.first_order_item?.quantity || 1);
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

    // Hinweis: Weitere Events (license_key_created, subscription_created/updated/cancelled) können wir später ergänzen.

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// --- JSON parser NACH raw webhook
app.use(express.json());

// -------- simple API for status / assign / release --------

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
  const { email, modelId, modelName } = req.body||{};
  if (!email || !String(email).includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db = loadDb();
  const acc = ensureAcc(db, String(email).toLowerCase());
  const seats = acc.seats || [];

  // schon belegt?
  if (seats.find(s=>s.assignedToModelId === modelId)){
    return res.json({ ok:true, msg:'already assigned' });
  }

  // freien Seat suchen
  const free = seats.find(s=>!s.assignedToModelId);
  if (!free) return res.status(409).json({ ok:false, msg:'no free seat' });

  free.assignedToModelId = modelId;
  free.assignedToModelName = modelName||null;

  saveDb(db);
  res.json({ ok:true, seatId: free.id });
});

// POST /api/licenses/release  { email, modelId }
app.post('/api/licenses/release', (req, res)=>{
  const { email, modelId } = req.body||{};
  if (!email || !String(email).includes('@')) return res.status(400).json({ ok:false, msg:'email missing' });
  if (!modelId) return res.status(400).json({ ok:false, msg:'modelId missing' });

  const db = loadDb();
  const acc = ensureAcc(db, String(email).toLowerCase());
  const seats = acc.seats || [];

  const seat = seats.find(s=>s.assignedToModelId === modelId);
  if (!seat) return res.json({ ok:true, msg:'already free' });

  seat.assignedToModelId = null;
  seat.assignedToModelName = null;

  saveDb(db);
  res.json({ ok:true });
});

// --- start
app.listen(port, () => {
  console.log(`License server listening on ${port}`);
});
