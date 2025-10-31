// server.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// ---- Konfiguration / Env ----
const PORT   = process.env.PORT || 10000;
// exakt gleich wie in Lemon Webhook-Einstellung
const SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';

// Optionale Vars (für spätere API-Validierungen – jetzt nicht zwingend nötig)
const LS_API_KEY = process.env.LEMONSQUEEZY_API_KEY || '';
const LS_STORE_ID = process.env.LEMONSQUEEZY_STORE_ID || '';

// ---- einfacher JSON "DB"-Pfad ----
const DB_FILE = path.join(__dirname, 'licenses.json');

// ---- Hilfsfunktionen Filespeicher ----
function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      return { customers: {} };
    }
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('[DB] read error:', e);
    return { customers: {} };
  }
}
function writeDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('[DB] write error:', e);
  }
}

// ---- CORS, Basic Security ----
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // Electron App darf zugreifen
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ---- Health ----
app.get('/',       (req, res) => res.status(200).send('OK'));
app.get('/health', (req, res) => res.status(200).send('OK'));

// =====================================
// ============ WEBHOOK =================
// =====================================
// Lemon sendet als RAW JSON. Wir brauchen den Roh-Body für HMAC.
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

app.post('/api/lemon/webhook', (req, res) => {
  try {
    const raw = req.body; // Buffer
    const hdrSig = req.get('X-Signature') || req.get('x-signature') || '';
    const event  = req.get('X-Event-Name') || req.get('x-event-name') || '';
    console.log('[Webhook] hit. event:', event, 'len=', raw?.length || 0);

    if (!SECRET) {
      console.log('[Webhook] missing SECRET');
      return res.status(500).send('missing secret');
    }
    if (!hdrSig) {
      console.log('[Webhook] missing signature header');
      return res.status(400).send('missing signature');
    }

    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');

    const valid = crypto.timingSafeEqual(Buffer.from(hdrSig), Buffer.from(digest));
    console.log('[Webhook] signature valid?', valid);
    if (!valid) return res.status(400).send('invalid signature');

    const payload = JSON.parse(raw.toString('utf8'));
    const metaName = payload?.meta?.event_name || event || 'unknown';
    console.log('[Webhook] meta.event_name:', metaName);

    // Wir interessieren uns hier primär für order_created (One-Time oder erstes Abo)
    if (metaName === 'order_created') {
      const attr = payload?.data?.attributes || {};
      const email = (attr.user_email || '').trim().toLowerCase();
      const qty = Number(attr?.first_order_item?.quantity ?? 1) || 1;
      const product_id = attr?.first_order_item?.product_id || null;
      const variant_id = attr?.first_order_item?.variant_id || null;
      const testMode = !!attr?.test_mode;

      if (!email) {
        console.log('[Webhook] order_created ohne email – wird ignoriert');
      } else {
        const db = readDB();
        if (!db.customers[email]) {
          db.customers[email] = {
            email,
            plan: 'basic',    // kannst du später anhand variant_id mappen
            seats_total: 0,
            seats_used: 0,
            seats_free: 0,
            seats: {},        // { modelId: true }
            orders: []
          };
        }
        // Seats erhöhen um Menge (qty)
        db.customers[email].seats_total += qty;
        db.customers[email].seats_free  = Math.max(0, db.customers[email].seats_total - db.customers[email].seats_used);
        db.customers[email].orders.push({
          order_id: payload?.data?.id,
          product_id,
          variant_id,
          qty,
          created_at: attr?.created_at,
          test_mode: testMode
        });
        writeDB(db);
        console.log(`[Webhook] Seats aktualisiert für ${email} – total=${db.customers[email].seats_total} used=${db.customers[email].seats_used}`);
      }
    }

    // Optional: subscription_created / subscription_updated / license_key_created etc. hier verarbeiten

    return res.status(200).send('ok');
  } catch (e) {
    console.error('[Webhook] error:', e);
    return res.status(500).send('error');
  }
});

// JSON Parser NACH dem Raw-Route
app.use(express.json());

// =====================================
// ============ LICENSE API ============
// =====================================

// Status je E-Mail
app.get('/api/licenses/status', (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ ok:false, error:'missing email' });
  const db = readDB();
  const c = db.customers[email];
  if (!c) return res.json({ ok:true, active:false, email, plan:null, seats_total:0, seats_used:0, seats_free:0 });

  const active = (c.seats_total - c.seats_used) >= 0 && c.seats_total > 0;
  return res.json({
    ok:true,
    active,
    email,
    plan: c.plan,
    seats_total: c.seats_total,
    seats_used: c.seats_used,
    seats_free: Math.max(0, c.seats_total - c.seats_used)
  });
});

// Alle (Debug)
app.get('/api/licenses', (req, res) => {
  const db = readDB();
  return res.json(db);
});

// Seat vergeben (z. B. beim Creator-Anlegen)
app.post('/api/licenses/assign', (req, res) => {
  const { email, modelId } = req.body || {};
  const e = (email||'').trim().toLowerCase();
  if (!e || !modelId) return res.status(400).json({ ok:false, error:'missing email or modelId' });

  const db = readDB();
  const c = db.customers[e];
  if (!c) return res.status(404).json({ ok:false, error:'customer not found' });

  if (c.seats[modelId]) {
    return res.json({ ok:true, message:'already assigned', seats_used:c.seats_used, seats_total:c.seats_total, seats_free: Math.max(0, c.seats_total - c.seats_used) });
  }

  const free = Math.max(0, c.seats_total - c.seats_used);
  if (free <= 0) return res.status(403).json({ ok:false, error:'no free seats' });

  c.seats[modelId] = true;
  c.seats_used += 1;
  writeDB(db);
  return res.json({ ok:true, seats_used:c.seats_used, seats_total:c.seats_total, seats_free: Math.max(0, c.seats_total - c.seats_used) });
});

// Seat freigeben (z. B. beim Creator-Löschen)
app.post('/api/licenses/release', (req, res) => {
  const { email, modelId } = req.body || {};
  const e = (email||'').trim().toLowerCase();
  if (!e || !modelId) return res.status(400).json({ ok:false, error:'missing email or modelId' });

  const db = readDB();
  const c = db.customers[e];
  if (!c) return res.status(404).json({ ok:false, error:'customer not found' });

  if (c.seats[modelId]) {
    delete c.seats[modelId];
    c.seats_used = Math.max(0, c.seats_used - 1);
    writeDB(db);
  }
  return res.json({ ok:true, seats_used:c.seats_used, seats_total:c.seats_total, seats_free: Math.max(0, c.seats_total - c.seats_used) });
});

// 404
app.use((req, res) => res.status(404).json({ ok:false, error:'not found' }));

app.listen(PORT, () => {
  console.log(`License server listening on :${PORT}`);
});
