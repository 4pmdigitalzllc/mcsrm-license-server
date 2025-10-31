const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 10000;
const SECRET = process.env.LEMONSQUEEZY_SIGNING_SECRET || '';

// Für Health & Root
app.get('/', (req, res) => res.status(200).send('OK'));
app.get('/health', (req, res) => res.status(200).send('ok'));

// 1) Roh-Body puffern, damit Signatur stimmt
app.use('/api/lemon/webhook', express.raw({ type: 'application/json' }));

// 2) Webhook-Route mit viel Logging
app.post('/api/lemon/webhook', (req, res) => {
  try {
    const raw = req.body; // Buffer
    const lsSig = req.get('X-Signature') || req.get('x-signature') || '';
    const event = req.get('X-Event-Name') || req.get('x-event-name') || '';
    console.log('[Webhook] request received. Event:', event);
    console.log('[Webhook] headers:', JSON.stringify(req.headers));

    if (!SECRET) {
      console.log('[Webhook] Kein SIGNING_SECRET gesetzt!');
      return res.status(500).send('missing secret');
    }
    if (!lsSig) {
      console.log('[Webhook] Keine X-Signature im Header.');
      return res.status(400).send('missing signature');
    }

    // HMAC-SHA256 über den RAW body
    const hmac = crypto.createHmac('sha256', SECRET);
    hmac.update(raw);
    const digest = hmac.digest('hex');

    const valid = crypto.timingSafeEqual(Buffer.from(lsSig), Buffer.from(digest));
    console.log('[Webhook] signature valid?', valid);

    if (!valid) return res.status(400).send('invalid signature');

    // gültig → JSON parsen und loggen
    const payload = JSON.parse(raw.toString('utf8'));
    console.log('[Webhook] payload.meta.event_name:', payload?.meta?.event_name);
    console.log('[Webhook] order id / subscription id:',
      payload?.data?.id || payload?.data?.attributes?.first_order_id);

    // hier würdest du dein Lizenzhandling machen …

    return res.status(200).send('ok');
  } catch (err) {
    console.error('[Webhook] error:', err);
    return res.status(500).send('error');
  }
});

// Fallback JSON-Parser NACH der Webhook-Route
app.use(express.json());

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
