// server.js
const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 10000;
const SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';

// --- Health & Root ---
app.get('/', (_req, res) => res.status(200).send('OK'));
app.get('/health', (_req, res) => res.status(200).send('ok'));

// --- WICHTIG: Roh-Body nur für den Webhook parsen ---
app.use('/api/lemon/webhook', express.raw({ type: 'application/json', limit: '200kb' }));

// --- Lemon Squeezy Webhook ---
app.post('/api/lemon/webhook', (req, res) => {
  try {
    const raw = req.body; // Buffer (weil express.raw)
    const lsSig = req.get('x-signature') || '';       // Signatur von Lemon Squeezy
    const eventHeader = req.get('x-event-name') || ''; // optionaler Event-Header

    console.log('---[Webhook] Incoming---');
    console.log('[Webhook] Event header:', eventHeader);
    console.log('[Webhook] Content-Type:', req.get('content-type'));
    console.log('[Webhook] Raw length:', raw?.length || 0);

    if (!SECRET) {
      console.warn('[Webhook] Kein LEMONSQUEEZY_SIGNING_SECRET gesetzt!');
      return res.status(500).send('missing secret');
    }
    if (!lsSig) {
      console.warn('[Webhook] Keine X-Signature im Header.');
      return res.status(400).send('missing signature');
    }

    // HMAC-SHA256 über den *rohen* Body bilden
    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');

    // Schutz: nur vergleichen, wenn gleich lang – sonst wirft timingSafeEqual
    if (lsSig.length !== digest.length) {
      console.warn('[Webhook] Signature length mismatch');
      return res.status(400).send('invalid signature');
    }

    const valid = crypto.timingSafeEqual(Buffer.from(lsSig), Buffer.from(digest));
    console.log('[Webhook] signature valid?', valid);
    if (!valid) return res.status(400).send('invalid signature');

    // Gültig → Payload parsen
    const payload = JSON.parse(raw.toString('utf8'));
    const eventName = payload?.meta?.event_name || '(unknown)';
    const orderId = payload?.data?.id || payload?.data?.attributes?.first_order_id;

    console.log('[Webhook] meta.event_name:', eventName);
    console.log('[Webhook] data.id / first_order_id:', orderId);

    // TODO: Hier dein Lizenz-/Abo-Handling einbauen (DB, E-Mail, etc.)

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// Alle anderen Routen: normales JSON
app.use(express.json());

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
