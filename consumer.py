"""
consumer.py — Secure Kafka Consumer
======================================
Reads encrypted AV events from Kafka, decrypts them, validates the payload,
and persists to PostgreSQL.  Security measures included:
  • Authentication-tag verification (GCM) — tampered messages are rejected
  • Parameterised SQL — no SQL injection possible
  • Security audit log — every failure is recorded
  • Dead-letter handling — bad messages are logged, not crashed on

Run:  python consumer.py
"""

import json
import logging
from cryptography.exceptions import InvalidTag
from kafka import KafkaConsumer
from kafka.errors import KafkaError

from config import KAFKA_BROKER, KAFKA_TOPIC, KAFKA_GROUP_ID
from encryption import decrypt
from db_setup import get_connection, insert_event, log_security_event, create_schema

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CONSUMER] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# ── Required fields in every event ────────────────────────────────────────────
REQUIRED_FIELDS = {"vehicle_id", "event_type", "severity", "timestamp"}


def validate_event(event: dict) -> bool:
    """Return True only if all required fields are present and non-empty."""
    for field in REQUIRED_FIELDS:
        if not event.get(field):
            return False
    return True


def process_message(raw_value: bytes, db_conn) -> bool:
    """
    Full pipeline for a single Kafka message:
      1. Decode bytes → encrypted string
      2. Decrypt with AES-256-GCM (raises InvalidTag if tampered)
      3. Parse JSON
      4. Validate required fields
      5. Insert into PostgreSQL

    Returns True on success, False on any error.
    """
    encrypted_str = raw_value.decode("utf-8")

    # ── Step 1: Decrypt ────────────────────────────────────────────────────────
    try:
        plaintext = decrypt(encrypted_str)
    except InvalidTag:
        # This means the message was tampered with or corrupted
        log.error("🔴 INTEGRITY FAILURE — message authentication tag invalid!")
        log_security_event(db_conn, "DECRYPT_FAIL_TAMPER",
                           "Invalid GCM tag — possible message tampering detected.")
        return False
    except Exception as exc:
        log.error("Decryption error: %s", exc)
        log_security_event(db_conn, "DECRYPT_FAIL_OTHER", str(exc))
        return False

    # ── Step 2: Parse JSON ─────────────────────────────────────────────────────
    try:
        event = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        log.error("JSON parse error: %s", exc)
        log_security_event(db_conn, "JSON_PARSE_FAIL", str(exc))
        return False

    # ── Step 3: Validate ───────────────────────────────────────────────────────
    if not validate_event(event):
        log.warning("Validation failed for event: %s", event)
        log_security_event(db_conn, "VALIDATION_FAIL",
                           f"Missing required fields. Payload: {json.dumps(event)}")
        return False

    # ── Step 4: Persist ────────────────────────────────────────────────────────
    try:
        insert_event(db_conn, event)
        log.info("✓ Stored: %s | %s | severity=%s",
                 event["vehicle_id"], event["event_type"], event["severity"])
        return True
    except Exception as exc:
        log.error("DB insert error: %s", exc)
        log_security_event(db_conn, "DB_INSERT_FAIL", str(exc))
        db_conn.rollback()          # keep connection healthy
        return False


def main():
    # Ensure tables exist
    create_schema()

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset="earliest",   # catch up from beginning if new consumer
        enable_auto_commit=False,        # manual commit → no data loss on crash
        value_deserializer=lambda v: v,  # keep as raw bytes; we decode ourselves
    )

    log.info("Consumer started. Listening on topic '%s' …", KAFKA_TOPIC)

    db_conn = get_connection()

    try:
        for message in consumer:
            success = process_message(message.value, db_conn)

            if success:
                # Commit only AFTER successful DB write (at-least-once delivery)
                consumer.commit()
            else:
                log.warning("Message at offset %d skipped (see audit log).",
                            message.offset)
                consumer.commit()   # still commit to avoid infinite retry loop

    except KeyboardInterrupt:
        log.info("Interrupted by user. Shutting down …")
    except KafkaError as exc:
        log.critical("Kafka error: %s", exc)
    finally:
        consumer.close()
        db_conn.close()
        log.info("Consumer closed.")


if __name__ == "__main__":
    main()