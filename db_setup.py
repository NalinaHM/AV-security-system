"""
db_setup.py — PostgreSQL Database Setup
=========================================
Run this ONCE before starting the consumer.
Creates the database schema with:
  • Parameterised queries (no raw string formatting → no SQL injection)
  • Indexes for fast lookup
  • Audit columns (created_at)
"""

import psycopg2
from psycopg2 import sql
from config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD


def get_connection():
    """Return a new psycopg2 connection. Reuse this helper everywhere."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        # Enforce SSL in production by adding: sslmode="require"
    )


def create_schema():
    """Create tables if they don't already exist."""
    conn = get_connection()
    try:
        with conn:                          # auto-commit / rollback on error
            with conn.cursor() as cur:

                # ── Main events table ──────────────────────────────────────────
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS av_events (
                        id            SERIAL PRIMARY KEY,
                        vehicle_id    VARCHAR(50)  NOT NULL,
                        event_type    VARCHAR(100) NOT NULL,
                        speed_kmh     FLOAT,
                        latitude      FLOAT,
                        longitude     FLOAT,
                        battery_pct   FLOAT,
                        severity      VARCHAR(20),
                        raw_payload   JSONB,          -- full decrypted payload
                        received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                """)

                # ── Index for fast per-vehicle lookups ─────────────────────────
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_av_events_vehicle
                    ON av_events (vehicle_id, received_at DESC);
                """)

                # ── Security audit log ─────────────────────────────────────────
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS security_audit (
                        id            SERIAL PRIMARY KEY,
                        event_type    VARCHAR(50)  NOT NULL,  -- e.g. DECRYPT_FAIL
                        detail        TEXT,
                        logged_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                """)

                print("[db_setup] Schema created / verified successfully.")
    finally:
        conn.close()


def insert_event(conn, event: dict):
    """
    Safely insert a decoded AV event using parameterised query.
    Always pass `conn` from get_connection() — never build SQL strings manually.
    """
    import json
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO av_events
                (vehicle_id, event_type, speed_kmh, latitude, longitude,
                 battery_pct, severity, raw_payload)
            VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event.get("vehicle_id"),
                event.get("event_type"),
                event.get("speed_kmh"),
                event.get("latitude"),
                event.get("longitude"),
                event.get("battery_pct"),
                event.get("severity"),
                json.dumps(event),              # store entire payload as JSONB
            )
        )
    conn.commit()


def log_security_event(conn, event_type: str, detail: str):
    """Write a record to the security audit table."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO security_audit (event_type, detail) VALUES (%s, %s)",
            (event_type, detail)
        )
    conn.commit()


if __name__ == "__main__":
    create_schema()