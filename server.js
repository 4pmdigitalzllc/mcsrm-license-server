const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 10000;
const SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';

app.set('trust proxy', true);

// --- Leichte Diagnose: jede Anfrage kurz loggen (ohne Body zu lesen!) ---
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.originalUrl}  ct=${req.headers['content-type'] || '-'}  ua=${req.headers['user-agent'] || '-'}`);
  next();
});

// Health & Root
app.get('/', (_req, res) => res.status(200).send('OK'));
app.get('/health', (_req, res) => res.status(200).send('ok'));

// WICHTIG: RAW Body auf der Webhook-Route – akzeptiere *alle* Typen
app.use('/api/lemon/webhook', express.raw({ type: '*/*' }));

app.post('/api/lemon/webhook', (req, res) => {
  try {
    const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
    const lsSig = req.get('X-Signature') || req.get('x-signature') || '';
    const event = req.get('X-Event-Name') || req.get('x-event-name') || '';

    console.log(`[Webhook] hit. event="${event}" len=${raw.length}B sigPresent=${!!lsSig}`);

    if (!SECRET) {
      console.log('[Webhook] ERROR: LEMONSQUEEZY_SIGNING_SECRET fehlt.');
      return res.status(500).send('missing secret');
    }
    if (!lsSig) {
      console.log('[Webhook] ERROR: X-Signature fehlt.');
      return res.status(400).send('missing signature');
    }
    if (!raw || raw.length === 0) {
      console.log('[Webhook] ERROR: raw body leer.');
      return res.status(400).send('empty body');
    }

    // HMAC über den RAW-Body
    const digest = crypto.createHmac('sha256', SECRET).update(raw).digest('hex');

    let valid = false;
    try {
      // Falls LS je "sha256=..." senden würde, den Präfix abwerfen
      const cleanSig = lsSig.startsWith('sha256=') ? lsSig.slice(7) : lsSig;
      valid = crypto.timingSafeEqual(Buffer.from(cleanSig), Buffer.from(digest));
    } catch {
      valid = false;
    }

    console.log(`[Webhook] signature valid? ${valid} (expected=${digest.slice(0,12)}…)`);
    if (!valid) return res.status(400).send('invalid signature');

    // gültig -> Payload auslesen
    const payload = JSON.parse(raw.toString('utf8'));
    console.log('[Webhook] meta.event_name:', payload?.meta?.event_name);
    console.log('[Webhook] data.id:', payload?.data?.id);

    // TODO: Lizenz-Handling hier …

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// JSON-Parser NACH der Webhook-Route
app.use(express.json());

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
