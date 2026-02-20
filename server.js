import express from "express";
import twilio from "twilio";
import pg from "pg";

const app = express();
app.use(express.urlencoded({ extended: false })); // Twilio manda form-urlencoded
app.use(express.json());

const clientTwilio = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

const db = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// ─── Helpers ────────────────────────────────────────────────────────────────

async function saveMessage({ supplierPhone, direction, channel, fromAddr, toAddr, body, raw }) {
  await db.query(
    `INSERT INTO messages (supplier_phone, direction, channel, from_addr, to_addr, body, raw)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [supplierPhone, direction, channel, fromAddr, toAddr, body, raw]
  );
}

function requireOpenclaw(req, res, next) {
  const key = req.header("x-openclaw-key");
  if (!key || key !== process.env.OPENCLAW_SHARED_SECRET) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  next();
}

// ─── Healthcheck ─────────────────────────────────────────────────────────────

app.get("/", (_req, res) => res.send("ok"));

// ─── Twilio Webhooks ─────────────────────────────────────────────────────────

// SMS inbound (original)
app.post("/twilio/sms-inbound", (req, res) => {
  const { From, To, Body } = req.body;
  console.log("📩 INBOUND SMS:", { From, To, Body });
  res.type("text/xml").send("<Response></Response>");
});

// Voice OTP recorder
app.post("/twilio/voice-otp", (req, res) => {
  res.type("text/xml").send(`
<Response>
  <Record maxLength="90" playBeep="false" />
  <Hangup/>
</Response>
`.trim());
});

// WhatsApp / SMS inbound general → guarda en DB
app.post("/twilio/inbound", async (req, res) => {
  const { From, To, Body } = req.body;
  const isWhatsApp = (From || "").startsWith("whatsapp:");
  const supplierPhone = isWhatsApp ? From.replace("whatsapp:", "") : From;

  await saveMessage({
    supplierPhone,
    direction: "inbound",
    channel: isWhatsApp ? "whatsapp" : "sms",
    fromAddr: From,
    toAddr: To,
    body: Body || "",
    raw: req.body,
  });

  console.log("💬 INBOUND", { From, To, Body });
  res.type("text/xml").send("<Response></Response>");
});

// ─── Sourcing API (protegida con x-openclaw-key) ──────────────────────────────

// A6: Subir draft list de proveedores
app.post("/sourcing/draft_list", requireOpenclaw, async (req, res) => {
  const { batch, suppliers } = req.body;

  const r = await db.query(
    `INSERT INTO rfq_batches (product, qty, incoterm, specs, status)
     VALUES ($1,$2,$3,$4,'draft') RETURNING id`,
    [batch?.product || "", batch?.qty || "", batch?.incoterm || "", batch?.specs || ""]
  );
  const batchId = r.rows[0].id;

  for (const s of suppliers || []) {
    const phone = (s.phone || "").replace(/\s+/g, "");
    if (!phone) continue;

    await db.query(
      `INSERT INTO suppliers (phone_e164, name, country, alibaba_url)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (phone_e164) DO UPDATE
         SET name=EXCLUDED.name, country=EXCLUDED.country, alibaba_url=EXCLUDED.alibaba_url`,
      [phone, s.name || null, s.country || null, s.alibaba_url || null]
    );

    await db.query(
      `INSERT INTO rfq_batch_suppliers (batch_id, supplier_phone, supplier_name, alibaba_url, approved)
       VALUES ($1,$2,$3,$4,false)
       ON CONFLICT (batch_id, supplier_phone) DO NOTHING`,
      [batchId, phone, s.name || null, s.alibaba_url || null]
    );
  }

  res.json({ ok: true, batchId });
});

// A7: Aprobar proveedores y mandar RFQ por WhatsApp template
app.post("/whatsapp/send_rfq_batch", requireOpenclaw, async (req, res) => {
  const { batchId, approvals } = req.body;

  for (const p of approvals || []) {
    await db.query(
      `UPDATE rfq_batch_suppliers SET approved=true WHERE batch_id=$1 AND supplier_phone=$2`,
      [batchId, p]
    );
  }

  const batch = (await db.query(`SELECT * FROM rfq_batches WHERE id=$1`, [batchId])).rows[0];
  const rows = (await db.query(
    `SELECT supplier_phone, supplier_name FROM rfq_batch_suppliers
     WHERE batch_id=$1 AND approved=true`,
    [batchId]
  )).rows;

  for (const s of rows) {
    const to   = `whatsapp:${s.supplier_phone}`;
    const from = process.env.TWILIO_WHATSAPP_FROM; // "whatsapp:+1..."

    const vars = {
      "1": s.supplier_name || "Sales team",
      "2": batch.product,
      "3": batch.qty,
      "4": batch.incoterm,
      "5": batch.specs,
    };

    const msg = await clientTwilio.messages.create({
      from,
      to,
      contentSid: process.env.RFQ_CONTENT_SID, // HX...
      contentVariables: JSON.stringify(vars),
    });

    await saveMessage({
      supplierPhone: s.supplier_phone,
      direction: "outbound",
      channel: "whatsapp",
      fromAddr: from,
      toAddr: to,
      body: `[TEMPLATE rfq_initial] ${JSON.stringify(vars)}`,
      raw: msg,
    });
  }

  await db.query(`UPDATE rfq_batches SET status='sent' WHERE id=$1`, [batchId]);
  res.json({ ok: true, sent: rows.length });
});

// ─── Dashboard (lectura rápida, sin UI) ──────────────────────────────────────

// Últimas conversaciones por proveedor
app.get("/dashboard/threads", requireOpenclaw, async (req, res) => {
  const r = await db.query(`
    SELECT
      supplier_phone,
      max(created_at) AS last_ts,
      (ARRAY_AGG(body ORDER BY created_at DESC))[1] AS last_body
    FROM messages
    WHERE channel='whatsapp'
    GROUP BY supplier_phone
    ORDER BY last_ts DESC
    LIMIT 200
  `);
  res.json(r.rows);
});

// Hilo completo de un proveedor
app.get("/dashboard/thread/:phone", requireOpenclaw, async (req, res) => {
  const phone = req.params.phone;
  const r = await db.query(`
    SELECT direction, body, created_at
    FROM messages
    WHERE supplier_phone=$1 AND channel='whatsapp'
    ORDER BY created_at ASC
    LIMIT 500
  `, [phone]);
  res.json(r.rows);
});

// ─── Start ───────────────────────────────────────────────────────────────────

app.listen(process.env.PORT || 3000, () => console.log("🚀 listening"));
