const express = require("express");
const app = express();

// Health check
app.get("/health", (req, res) => res.status(200).send("ok"));

// LemonSqueezy webhook
app.post("/api/lemon/webhook", express.raw({ type: "*/*" }), (req, res) => {
  console.log("Webhook received");
  res.status(200).send("ok");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`📬 Listening on port ${PORT}`));
