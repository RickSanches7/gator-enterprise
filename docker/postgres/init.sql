-- ═══════════════════════════════════════════════════════════
-- GATOR PRO ENTERPRISE — PostgreSQL Init Script
-- Runs once on first container start
-- ═══════════════════════════════════════════════════════════

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- for text search
CREATE EXTENSION IF NOT EXISTS "btree_gin";  -- for JSONB indexes

-- Default admin user (password: GatorAdmin2024! — change immediately)
-- Hashed with bcrypt
-- To generate: python3 -c "from passlib.hash import bcrypt; print(bcrypt.hash('GatorAdmin2024!'))"

-- Will be inserted by Alembic migration
-- This file just ensures extensions exist

COMMENT ON DATABASE gator_enterprise IS 'GATOR PRO Enterprise — Banking Pentest Platform';
