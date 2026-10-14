-- ============================================================
--  IronLedger — Supabase Schema (V2.1 Hardened)
--  Run this script in the Supabase SQL Editor:
--  https://app.supabase.com → Your Project → SQL Editor → New Query
-- ============================================================

-- ── 0. Optional: Reset stale rows from previous schema versions ──
-- TRUNCATE public.ics_events CASCADE;
-- TRUNCATE public.blockchain_blocks CASCADE;

-- ── 1. ICS Events (off-chain mutable database) ──────────────
CREATE TABLE IF NOT EXISTS public.ics_events (
    event_id             BIGINT PRIMARY KEY,
    timestamp            DOUBLE PRECISION NOT NULL,
    timestamp_ms         BIGINT,
    source               TEXT NOT NULL,
    command_type         TEXT NOT NULL,
    entity_id            TEXT NOT NULL,
    parameters           TEXT DEFAULT '{}',        -- JSON string
    plant_state_snapshot TEXT DEFAULT '{}',        -- JSON string
    signature            TEXT,                     -- HMAC/ECDSA command signature
    created_at           TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE public.ics_events IS
    'Off-chain ICS command event log — the mutable database that can be tampered with. '
    'Cryptographic state hashes in blockchain_blocks expose any unauthorized alteration here.';

-- ── 2. Blockchain Blocks (immutable ledger mirror) ──────────
CREATE TABLE IF NOT EXISTS public.blockchain_blocks (
    block_index   BIGINT PRIMARY KEY,
    event_id      BIGINT REFERENCES public.ics_events(event_id) ON DELETE RESTRICT,
    event_hash    TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    timestamp     BIGINT NOT NULL,
    timestamp_ms  BIGINT,
    source        TEXT NOT NULL,
    command_type  TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    parameters    TEXT DEFAULT '{}',        -- JSON string: authentic command parameters
    tx_hash       TEXT,
    block_number  BIGINT,
    recorded_by   TEXT,
    status        TEXT DEFAULT 'CONFIRMED_ON_CHAIN',
    is_simulated  BOOLEAN DEFAULT TRUE,
    etherscan_url TEXT,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE public.blockchain_blocks IS
    'Mirror of the immutable blockchain anchor ledger. '
    'event_hash is the SHA-256 state digest anchored on Ethereum Sepolia or local cryptographic chain.';

-- ── 3. Forensic Cases (saved investigation records) ─────────
CREATE TABLE IF NOT EXISTS public.forensic_cases (
    id                   BIGSERIAL PRIMARY KEY,
    case_name            TEXT NOT NULL,
    attack_scenario      TEXT,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    events_analyzed      INT DEFAULT 0,
    tamper_detected      BOOLEAN DEFAULT FALSE,
    tampered_records     INT DEFAULT 0,
    root_cause_source    TEXT,
    root_cause_command   TEXT,
    root_cause_entity    TEXT,
    forensic_conclusion  TEXT,
    attribution_actor    TEXT,
    confidence_score     REAL DEFAULT 0,
    mitre_techniques     TEXT DEFAULT '[]',    -- JSON array string
    timeline             TEXT DEFAULT '[]',    -- JSON array string
    threat_intel         TEXT DEFAULT '{}',    -- JSON object string
    telemetry_snapshot   TEXT DEFAULT '{}'     -- JSON object string
);

-- ── 3b. Migrations for Pre-Existing Tables ────────────────────
-- CREATE TABLE IF NOT EXISTS will not change column types of tables that already exist.
-- The following statements safely alter existing JSONB columns to TEXT if run against an existing schema:
ALTER TABLE IF EXISTS public.ics_events 
    ALTER COLUMN parameters TYPE TEXT USING parameters::TEXT,
    ALTER COLUMN plant_state_snapshot TYPE TEXT USING plant_state_snapshot::TEXT;

ALTER TABLE IF EXISTS public.forensic_cases 
    ALTER COLUMN mitre_techniques TYPE TEXT USING mitre_techniques::TEXT,
    ALTER COLUMN timeline TYPE TEXT USING timeline::TEXT,
    ALTER COLUMN threat_intel TYPE TEXT USING threat_intel::TEXT,
    ALTER COLUMN telemetry_snapshot TYPE TEXT USING telemetry_snapshot::TEXT;

-- V2.2: Add parameters column to blockchain_blocks for tamper-proof parameter storage
ALTER TABLE IF EXISTS public.blockchain_blocks
    ADD COLUMN IF NOT EXISTS parameters TEXT DEFAULT '{}';

-- ── 4. Row-Level Security (RLS) ──────────────────────────────
ALTER TABLE public.ics_events        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blockchain_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.forensic_cases    ENABLE ROW LEVEL SECURITY;

-- Allow service-role ALL access
DROP POLICY IF EXISTS "anon_read_ics" ON public.ics_events;
DROP POLICY IF EXISTS "anon_read_blocks" ON public.blockchain_blocks;
DROP POLICY IF EXISTS "anon_read_cases" ON public.forensic_cases;

DROP POLICY IF EXISTS "service_write_ics" ON public.ics_events;
CREATE POLICY "service_write_ics" ON public.ics_events FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS "service_write_blocks" ON public.blockchain_blocks;
CREATE POLICY "service_write_blocks" ON public.blockchain_blocks FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS "service_write_cases" ON public.forensic_cases;
CREATE POLICY "service_write_cases" ON public.forensic_cases FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

-- ── 5. Indexes ───────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_ics_events_timestamp        ON public.ics_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_blockchain_blocks_event_id  ON public.blockchain_blocks(event_id);
CREATE INDEX IF NOT EXISTS idx_forensic_cases_created_at   ON public.forensic_cases(created_at DESC);
