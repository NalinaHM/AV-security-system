"""
config.py — Central Configuration
===================================
All settings are loaded from environment variables.
Copy `.env.example` to `.env` and fill in your values before running.
"""

import os
from dotenv import load_dotenv

load_dotenv()  # reads the .env file automatically

# ── Kafka Settings ─────────────────────────────────────────────────────────────
KAFKA_BROKER    = os.getenv("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC     = os.getenv("KAFKA_TOPIC", "av_events")
KAFKA_GROUP_ID  = os.getenv("KAFKA_GROUP_ID", "av_consumer_group")

# ── PostgreSQL Settings ────────────────────────────────────────────────────────
DB_HOST         = os.getenv("DB_HOST", "localhost")
DB_PORT         = os.getenv("DB_PORT", "5432")
DB_NAME         = os.getenv("DB_NAME", "av_events_db")
DB_USER         = os.getenv("DB_USER", "av_user")
DB_PASSWORD     = os.getenv("DB_PASSWORD", "change_me_in_env")

# ── AES-256 Key ────────────────────────────────────────────────────────────────
# MUST be exactly 32 bytes (256 bits).
# In production: store in a secrets manager (AWS KMS, HashiCorp Vault, etc.)
_raw_key = os.getenv("AES_KEY", "MySecure32ByteKeyForAES256Encr!!")
assert len(_raw_key.encode()) == 32, "AES_KEY must be exactly 32 bytes!"
AES_KEY: bytes = _raw_key.encode()