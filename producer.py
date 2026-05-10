
"""
producer.py — Secure Kafka Producer
======================================
Simulates a fleet of Autonomous Vehicles generating real-time events.
Each event is:
  1. Generated as a JSON payload
  2. Encrypted with AES-256-GCM
  3. Published to the Kafka topic

Run:  python producer.py
"""

import json
import time
import random
import logging
from datetime import datetime, timezone
from kafka import KafkaProducer
from kafka.errors import KafkaError
from faker import Faker

from config import KAFKA_BROKER, KAFKA_TOPIC
from encryption import encrypt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PRODUCER] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)
fake = Faker()

# ── Simulated event catalogue ──────────────────────────────────────────────────
EVENT_TYPES = [
    ("HARD_BRAKE",       "HIGH"),
    ("LANE_CHANGE",      "LOW"),
    ("OBSTACLE_DETECT",  "MEDIUM"),
    ("SPEED_EXCEED",     "HIGH"),
    ("BATTERY_LOW",      "MEDIUM"),
    ("SENSOR_FAULT",     "CRITICAL"),
    ("NORMAL_CRUISE",    "LOW"),
    ("EMERGENCY_STOP",   "CRITICAL"),
]

VEHICLE_IDS = [f"AV-{str(i).zfill(3)}" for i in range(1, 11)]   # AV-001 … AV-010


def generate_av_event() -> dict:
    """Create a realistic AV telemetry event."""
    event_type, severity = random.choice(EVENT_TYPES)
    return {
        "vehicle_id":   random.choice(VEHICLE_IDS),
        "event_type":   event_type,
        "severity":     severity,
        "speed_kmh":    round(random.uniform(0, 130), 2),
        "latitude":     round(float(fake.latitude()), 6),
        "longitude":    round(float(fake.longitude()), 6),
        "battery_pct":  round(random.uniform(5, 100), 1),
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }


def on_send_success(record_metadata):
    log.info(
        "✓ Sent → topic=%s partition=%d offset=%d",
        record_metadata.topic,
        record_metadata.partition,
        record_metadata.offset,
    )


def on_send_error(exc):
    log.error("✗ Failed to send message: %s", exc)


def main(interval_sec: float = 1.0, max_events: int = None):
    """
    Publish encrypted AV events to Kafka.

    Args:
        interval_sec: pause between events (default 1 s).
        max_events:   stop after N events; None = run forever.
    """
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        # Serialize the already-encrypted string to bytes
        value_serializer=lambda v: v.encode("utf-8"),
        # Retry up to 5 times on transient failures
        retries=5,
        # Ensure all replicas acknowledge the write (durability)
        acks="all",
    )

    log.info("Producer started. Publishing to topic '%s' …", KAFKA_TOPIC)
    count = 0

    try:
        while True:
            event        = generate_av_event()
            payload_json = json.dumps(event)
            encrypted    = encrypt(payload_json)        # ← AES-256-GCM here

            future = producer.send(
                KAFKA_TOPIC,
                value=encrypted,
                key=event["vehicle_id"].encode("utf-8"),  # partition by vehicle
            )
            future.add_callback(on_send_success)
            future.add_errback(on_send_error)

            log.info("Event queued: %s | %s | severity=%s",
                     event["vehicle_id"], event["event_type"], event["severity"])

            count += 1
            if max_events and count >= max_events:
                log.info("Reached max_events=%d. Stopping.", max_events)
                break

            time.sleep(interval_sec)

    except KeyboardInterrupt:
        log.info("Interrupted by user.")
    finally:
        producer.flush()
        producer.close()
        log.info("Producer closed. Total events sent: %d", count)


if __name__ == "__main__":
    main(interval_sec=1.0)   # one event per second; change as needed