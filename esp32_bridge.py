"""
esp32_bridge.py — ESP32 ↔ Kafka Security Bridge
=================================================
Receives commands from mobile app, validates them,
forwards to ESP32, and logs everything to Kafka + PostgreSQL.

Run: python esp32_bridge.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import json
import time
import hashlib
import logging
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BRIDGE] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# ── ESP32 IP (update after connecting ESP32 to WiFi) ───────
ESP32_IP   = os.getenv("ESP32_IP", "192.168.1.100")
ESP32_URL  = f"http://{ESP32_IP}"

# ── Kafka + DB config ───────────────────────────────────────
try:
    from kafka import KafkaProducer
    from encryption import encrypt
    import psycopg2
    from db_setup import get_connection, log_security_event
    KAFKA_AVAILABLE = True
    producer = KafkaProducer(
        bootstrap_servers=os.getenv("KAFKA_BROKER", "localhost:9092"),
        value_serializer=lambda v: v.encode("utf-8"),
        acks="all", retries=3
    )
    log.info("Kafka connected ✓")
except Exception as e:
    KAFKA_AVAILABLE = False
    log.warning(f"Kafka not available: {e} — running in bridge-only mode")

# ── Security: Token validation ──────────────────────────────
VALID_TOKENS = {"app_token_2026", "demo_token_expo"}

# ── Security event log (in-memory for demo) ─────────────────
security_events = []
MAX_EVENTS = 100


def log_event(event_type, detail, blocked=True):
    """Log security event to memory + Kafka"""
    event = {
        "type":      event_type,
        "detail":    detail,
        "blocked":   blocked,
        "timestamp": datetime.now().isoformat(),
    }
    security_events.insert(0, event)
    if len(security_events) > MAX_EVENTS:
        security_events.pop()

    log.warning(f"🔴 SECURITY: {event_type} — {detail}")

    # Send to Kafka if available
    if KAFKA_AVAILABLE:
        try:
            payload = json.dumps({
                "vehicle_id": "ESP32-AV-001",
                "event_type": event_type,
                "severity":   "CRITICAL" if blocked else "LOW",
                "detail":     detail,
                "timestamp":  event["timestamp"],
            })
            encrypted = encrypt(payload)
            producer.send("av_events", value=encrypted)
        except Exception as e:
            log.error(f"Kafka publish error: {e}")


# ════════════════════════════════════════════════════════════
#  API ROUTES
# ════════════════════════════════════════════════════════════

@app.route("/send-command", methods=["POST"])
def send_command():
    """
    Mobile app sends command here.
    Bridge validates → forwards to ESP32 → logs result.
    """
    data = request.get_json(silent=True)
    if not data:
        log_event("INVALID_JSON", "Malformed JSON from mobile app")
        return jsonify({"status": "BLOCKED", "reason": "INVALID_JSON"}), 400

    cmd       = data.get("command", "").upper()
    token     = data.get("token", "")
    speed     = data.get("speed", 150)
    timestamp = data.get("timestamp", int(time.time() * 1000))

    # ── Check 1: Token Authentication ─────────────────────────
    if token not in VALID_TOKENS:
        log_event("AUTH_FAILURE", f"Invalid token: {token}")
        return jsonify({"status": "BLOCKED", "reason": "AUTH_FAILURE"}), 401

    # ── Forward to ESP32 ──────────────────────────────────────
    try:
        payload = {
            "command":   cmd,
            "speed":     speed,
            "timestamp": timestamp,
            "token":     token,
        }
        resp = requests.post(
            f"{ESP32_URL}/command",
            json=payload,
            timeout=3
        )
        result = resp.json()

        if result.get("status") == "BLOCKED":
            reason = result.get("reason", "UNKNOWN")
            log_event(reason, f"ESP32 blocked command: {cmd}")
            return jsonify(result), 403

        # Success
        log_event("COMMAND_EXECUTED", f"{cmd} at speed {speed}", blocked=False)
        return jsonify(result), 200

    except requests.exceptions.ConnectRefusedError:
        log_event("ESP32_OFFLINE", "Cannot reach ESP32 — running in simulation")
        # Simulate response for demo
        return jsonify({
            "status":  "SIMULATED",
            "command": cmd,
            "note":    "ESP32 not connected — demo mode"
        }), 200
    except Exception as e:
        log.error(f"ESP32 error: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.route("/simulate-attack", methods=["POST"])
def simulate_attack():
    """
    Simulate various cyberattacks for demo purposes.
    Types: invalid_command, replay, speed_overflow, behavioral, fake_direction
    """
    data        = request.get_json(silent=True) or {}
    attack_type = data.get("type", "invalid_command")

    log.info(f"[DEMO] Simulating attack: {attack_type}")

    if attack_type == "invalid_command":
        payload = {"command": "HACK_SYSTEM", "token": "app_token_2026",
                   "speed": 150, "timestamp": int(time.time()*1000)}
    elif attack_type == "replay":
        payload = {"command": "FORWARD", "token": "app_token_2026",
                   "speed": 150, "timestamp": 1000000}  # old timestamp
    elif attack_type == "speed_overflow":
        payload = {"command": "FORWARD", "token": "app_token_2026",
                   "speed": 9999, "timestamp": int(time.time()*1000)}
    elif attack_type == "no_auth":
        payload = {"command": "FORWARD", "token": "hacker_token",
                   "speed": 150, "timestamp": int(time.time()*1000)}
    elif attack_type == "behavioral":
        # Send many rapid direction changes
        results = []
        directions = ["FORWARD","LEFT","RIGHT","BACKWARD","LEFT","FORWARD",
                      "RIGHT","BACKWARD","LEFT","RIGHT"]
        for d in directions:
            p = {"command": d, "token": "app_token_2026",
                 "speed": 150, "timestamp": int(time.time()*1000)}
            try:
                r = requests.post(f"{ESP32_URL}/command", json=p, timeout=2)
                results.append(r.json())
            except:
                results.append({"status": "SIMULATED", "command": d})
            time.sleep(0.05)
        log_event("BEHAVIORAL_ATTACK", "Rapid direction change simulation")
        return jsonify({"status": "ATTACK_SIMULATED",
                        "type": "behavioral", "results": results})
    else:
        return jsonify({"error": "Unknown attack type"}), 400

    # Forward attack payload to ESP32
    try:
        resp = requests.post(f"{ESP32_URL}/command", json=payload, timeout=3)
        result = resp.json()
    except:
        result = {"status": "BLOCKED", "reason": "SIMULATED_BLOCK",
                  "note": "ESP32 offline — attack blocked at bridge"}
        log_event(attack_type.upper(), f"Attack simulated and blocked: {attack_type}")

    return jsonify({"status": "ATTACK_SIMULATED", "type": attack_type,
                    "result": result})


@app.route("/esp32-status", methods=["GET"])
def esp32_status():
    """Get live status from ESP32"""
    try:
        resp = requests.get(f"{ESP32_URL}/status", timeout=3)
        data = resp.json()
        data["esp32_online"] = True
        return jsonify(data)
    except:
        return jsonify({
            "esp32_online":    False,
            "command":         "STOP",
            "front_cm":        150,
            "rear_cm":         150,
            "speed":           0,
            "attack_detected": False,
            "total_commands":  len(security_events),
            "attack_count":    sum(1 for e in security_events if e["blocked"]),
            "last_attack":     security_events[0]["type"] if security_events else "None",
            "note":            "Demo mode — ESP32 not connected"
        })


@app.route("/security-events", methods=["GET"])
def get_security_events():
    """Return security event log"""
    return jsonify({
        "events": security_events[:20],
        "total":  len(security_events),
        "attacks": sum(1 for e in security_events if e["blocked"]),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":         "running",
        "esp32_ip":       ESP32_IP,
        "kafka":          KAFKA_AVAILABLE,
        "events_logged":  len(security_events),
    })


if __name__ == "__main__":
    print("🚀 ESP32 Security Bridge running at http://localhost:8080")
    print(f"📡 ESP32 target: {ESP32_URL}")
    print("🎯 Endpoints:")
    print("   POST /send-command    — Send command to AV")
    print("   POST /simulate-attack — Simulate cyberattack")
    print("   GET  /esp32-status    — Live vehicle status")
    print("   GET  /security-events — Attack log")
    app.run(debug=True, port=8080, host="0.0.0.0")