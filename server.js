const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 10000;
const SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';

// --- Health & Root (damit Render nicht nur die Splash zeigt) ---
app.get('/', (req, res) => res.status(200).send('OK'));
app.get('/health', (req, res) => res.status(200).send('ok'));

// --- Helper: akzeptiere application/json ODER application/vnd.api+json ---
const rawJson = express.raw({
  type: (req) => {
    const ct = (req.headers['content-type'] || '').toLowerCase();
    return ct.includes('application/json') || ct.includes('application/vnd.api+json');
  }
});

// --- Dieselbe Webhook-Logik auf zwei Pfaden zulassen (falls sich die URL vertut) ---
const WEBHOOK_PATHS = ['/api/lemon/webhook', '/lemon/webhook'];

// Webhook-Handler
function handleWebhook(req, res) {
  try {
    const raw = req.body; // Buffer (weil express.raw)
    const sig = req.get('x-signature') || '';
    const eventHeader = req.get('x-event-name') || '';
    console.log('---- WEBHOOK HIT ----');
    console.log('Path:', req.path);
    console.log('Event header:', eventHeader);
    console.log('Content-Type:', req.get('content-type'));
    console.log('All headers:', JSON.stringify(req.headers));

    if (!SECRET) {
      console.log('!! Kein SIGNING_SECRET gesetzt');
      return res.status(500).send('missing secret');
    }
    if (!sig) {
      console.log('!! Keine X-Signature im Header');
      return res.status(400).send('missing signature');
    }
    if (!Buffer.isBuffer(raw)) {
      console.log('!! Body ist kein Buffer (Parser falsch?)');
      return res.status(400).send('invalid body');
    }

    // HMAC bilden und sicher vergleichen
    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');

    if (sig.length !== digest.length) {
      console.log('!! Signature length mismatch');
      return res.status(400).send('invalid signature');
    }
    const valid = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(digest));
    console.log('Signature valid?', valid);
    if (!valid) return res.status(400).send('invalid signature');

    // Payload parsen & kurz loggen
    const payload = JSON.parse(raw.toString('utf8'));
    console.log('meta.event_name:', payload?.meta?.event_name);
    console.log('data.id:', payload?.data?.id);

    // TODO: Hier dein Lizenz-Handling

    return res.status(200).send('ok');
  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).send('error');
  }
}

// Die Routen registrieren (beide Pfade)
for (const p of WEBHOOK_PATHS) {
  app.post(p, rawJson, handleWebhook);
}

// --- Debug: fängt alle POSTs ab und loggt (hilft beim 404-Suchen) ---
app.post('*', express.raw({ type: '*/*' }), (req, res) => {
  console.log('Unmatched POST:', req.path, 'CT=', req.get('content-type'));
  return res.status(404).send('no route for ' + req.path);
});

// JSON-Parser NACH dem Webhook (damit dort der RAW-Body verfügbar bleibt)
app.use(express.json());

app.listen(port, () => {
  // SECRET gekürzt loggen (nur zur Kontrolle während Tests)
  const tail = SECRET ? SECRET.slice(-6) : 'none';
  console.log(`Listening on port ${port} | SECRET tail: ${tail}`);
});
