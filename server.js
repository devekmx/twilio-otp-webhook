import express from "express";
import twilio from "twilio";
import pg from "pg";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const clientTwilio = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

const db = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function saveMessage({ supplierPhone, direction, channel, fromAddr, toAddr, body, raw }) {
  await db.query(
    `INSERT INTO messages (supplier_phone, direction, channel, from_addr, to_addr, body, raw)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [supplierPhone, direction, channel, fromAddr, toAddr, body, raw]
  );
}

function requireOpenclaw(req, res, next) {
  // Acepta header x-openclaw-key O query param ?key=...
  const key = req.header("x-openclaw-key") || req.query.key;
  if (!key || key !== process.env.OPENCLAW_SHARED_SECRET) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  next();
}

// ─── Static UI ───────────────────────────────────────────────────────────────

app.use("/ui", requireOpenclaw, express.static(join(__dirname, "public")));
app.get("/ui", requireOpenclaw, (_req, res) => res.sendFile(join(__dirname, "public", "index.html")));

// ─── Healthcheck ─────────────────────────────────────────────────────────────

app.get("/", (_req, res) => res.send("ok"));

// ─── Twilio Webhooks ─────────────────────────────────────────────────────────

app.post("/twilio/sms-inbound", (req, res) => {
  const { From, To, Body } = req.body;
  console.log("📩 INBOUND SMS:", { From, To, Body });
  res.type("text/xml").send("<Response></Response>");
});

app.post("/twilio/voice-otp", (req, res) => {
  res.type("text/xml").send(`
<Response>
  <Record maxLength="90" playBeep="false" />
  <Hangup/>
</Response>
`.trim());
});

app.post("/twilio/inbound", async (req, res) => {
  try {
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
  } catch (e) {
    console.error("inbound error", e);
  }
  res.type("text/xml").send("<Response></Response>");
});

// ─── Sourcing API ─────────────────────────────────────────────────────────────

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

// Enviar RFQ template inicial a proveedores aprobados
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
    `SELECT supplier_phone, supplier_name FROM rfq_batch_suppliers WHERE batch_id=$1 AND approved=true`,
    [batchId]
  )).rows;

  const results = [];
  for (const s of rows) {
    try {
      const to   = `whatsapp:${s.supplier_phone}`;
      const from = process.env.TWILIO_WHATSAPP_FROM;
      const vars = {
        "1": s.supplier_name || "Sales team",
        "2": batch.product,
        "3": batch.qty,
        "4": batch.incoterm,
        "5": batch.specs,
      };

      const msg = await clientTwilio.messages.create({
        from, to,
        contentSid: process.env.RFQ_CONTENT_SID,
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
      results.push({ phone: s.supplier_phone, ok: true, sid: msg.sid });
    } catch (e) {
      results.push({ phone: s.supplier_phone, ok: false, error: e.message });
    }
  }

  await db.query(`UPDATE rfq_batches SET status='sent' WHERE id=$1`, [batchId]);
  res.json({ ok: true, sent: results.filter(r => r.ok).length, results });
});

// Enviar mensaje libre (dentro de ventana 24h activa)
app.post("/whatsapp/send_message", requireOpenclaw, async (req, res) => {
  const { to, body } = req.body; // to = "+8613..." (sin prefijo whatsapp:)
  if (!to || !body) return res.status(400).json({ ok: false, error: "to y body requeridos" });

  const from = process.env.TWILIO_WHATSAPP_FROM;
  const toAddr = `whatsapp:${to}`;

  try {
    const msg = await clientTwilio.messages.create({ from, to: toAddr, body });

    await saveMessage({
      supplierPhone: to,
      direction: "outbound",
      channel: "whatsapp",
      fromAddr: from,
      toAddr,
      body,
      raw: msg,
    });

    res.json({ ok: true, sid: msg.sid });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ─── Dashboard API ────────────────────────────────────────────────────────────

app.get("/dashboard/threads", requireOpenclaw, async (req, res) => {
  const r = await db.query(`
    SELECT
      m.supplier_phone,
      s.name AS supplier_name,
      s.alibaba_url,
      max(m.created_at) AS last_ts,
      (ARRAY_AGG(m.body ORDER BY m.created_at DESC))[1] AS last_body,
      count(*) FILTER (WHERE m.direction = 'inbound') AS unread_count
    FROM messages m
    LEFT JOIN suppliers s ON s.phone_e164 = m.supplier_phone
    WHERE m.channel = 'whatsapp'
    GROUP BY m.supplier_phone, s.name, s.alibaba_url
    ORDER BY last_ts DESC
    LIMIT 200
  `);
  res.json(r.rows);
});

app.get("/dashboard/thread/:phone", requireOpenclaw, async (req, res) => {
  const phone = decodeURIComponent(req.params.phone);
  const r = await db.query(`
    SELECT direction, body, created_at
    FROM messages
    WHERE supplier_phone = $1 AND channel = 'whatsapp'
    ORDER BY created_at ASC
    LIMIT 500
  `, [phone]);
  res.json(r.rows);
});

app.get("/dashboard/supplier/:phone", requireOpenclaw, async (req, res) => {
  const phone = decodeURIComponent(req.params.phone);
  const r = await db.query(`SELECT * FROM suppliers WHERE phone_e164 = $1`, [phone]);
  res.json(r.rows[0] || null);
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(process.env.PORT || 3000, () => console.log("🚀 listening"));
