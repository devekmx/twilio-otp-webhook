import pg from "pg";
const { Client } = pg;

async function main() {
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  await client.query(`
    CREATE TABLE IF NOT EXISTS suppliers (
      id          SERIAL PRIMARY KEY,
      phone_e164  TEXT UNIQUE,
      name        TEXT,
      country     TEXT,
      alibaba_url TEXT,
      notes       TEXT,
      created_at  TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id             SERIAL PRIMARY KEY,
      supplier_phone TEXT,
      direction      TEXT CHECK (direction IN ('inbound','outbound')),
      channel        TEXT,
      from_addr      TEXT,
      to_addr        TEXT,
      body           TEXT,
      raw            JSONB,
      created_at     TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS rfq_batches (
      id         SERIAL PRIMARY KEY,
      status     TEXT DEFAULT 'draft',
      product    TEXT,
      qty        TEXT,
      incoterm   TEXT,
      specs      TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS rfq_batch_suppliers (
      batch_id       INT REFERENCES rfq_batches(id) ON DELETE CASCADE,
      supplier_phone TEXT,
      supplier_name  TEXT,
      alibaba_url    TEXT,
      approved       BOOLEAN DEFAULT false,
      PRIMARY KEY (batch_id, supplier_phone)
    );
  `);

  console.log("✅ DB initialized");
  await client.end();
}

main().catch((e) => { console.error(e); process.exit(1); });
