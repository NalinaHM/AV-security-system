"""
anomaly_detection.py — ML Anomaly Detection for AV Security
=============================================================
Uses Isolation Forest algorithm to detect unusual AV behavior.

Install: pip install scikit-learn pandas numpy
Run:     python anomaly_detection.py
"""

import psycopg2
import psycopg2.extras
import numpy as np
import json
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# ── Try to import sklearn ──────────────────────────────────────────────────
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import LabelEncoder
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[WARNING] scikit-learn not installed. Run: pip install scikit-learn")

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     os.getenv("DB_PORT", "5433"),
    "dbname":   os.getenv("DB_NAME", "av_events_db"),
    "user":     os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres123"),
}

# ── Event severity scores ──────────────────────────────────────────────────
SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
EVENT_SCORE    = {
    "NORMAL_CRUISE": 1, "LANE_CHANGE": 2,
    "BATTERY_LOW": 3,   "OBSTACLE_DETECT": 3,
    "HARD_BRAKE": 4,    "SPEED_EXCEED": 4,
    "SENSOR_FAULT": 5,  "EMERGENCY_STOP": 5,
}


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def create_anomaly_table():
    """Create table to store ML results"""
    conn = get_conn()
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_scores (
                    id            SERIAL PRIMARY KEY,
                    vehicle_id    VARCHAR(50),
                    event_type    VARCHAR(100),
                    severity      VARCHAR(20),
                    speed_kmh     FLOAT,
                    anomaly_score FLOAT,
                    is_anomaly    BOOLEAN,
                    risk_level    VARCHAR(20),
                    detected_at   TIMESTAMPTZ DEFAULT NOW()
                );
            """)
    conn.close()
    print("[ML] Anomaly table created ✓")


def fetch_events():
    """Fetch recent events from PostgreSQL"""
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT vehicle_id, event_type, severity, speed_kmh, battery_pct
            FROM av_events
            WHERE speed_kmh IS NOT NULL
            ORDER BY received_at DESC
            LIMIT 1000
        """)
        rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def prepare_features(events):
    """Convert events to ML feature matrix"""
    features = []
    for e in events:
        speed     = float(e.get("speed_kmh") or 60)
        battery   = float(e.get("battery_pct") or 50)
        sev_score = SEVERITY_SCORE.get(e.get("severity", "LOW"), 1)
        evt_score = EVENT_SCORE.get(e.get("event_type", "NORMAL_CRUISE"), 1)
        features.append([speed, battery, sev_score, evt_score])
    return np.array(features)


def rule_based_anomaly(event):
    """
    Simple rule-based detection (works without scikit-learn).
    Returns (is_anomaly, risk_level, reason)
    """
    speed    = float(event.get("speed_kmh") or 0)
    battery  = float(event.get("battery_pct") or 100)
    severity = event.get("severity", "LOW")
    evt_type = event.get("event_type", "")

    anomalies = []

    if speed > 120:
        anomalies.append(f"Extreme speed: {speed:.1f} km/h")
    if speed < 5 and evt_type not in ["EMERGENCY_STOP"]:
        anomalies.append(f"Suspicious near-stop: {speed:.1f} km/h")
    if battery < 10:
        anomalies.append(f"Critical battery: {battery:.1f}%")
    if evt_type == "SENSOR_FAULT":
        anomalies.append("Sensor malfunction detected")
    if evt_type == "EMERGENCY_STOP":
        anomalies.append("Emergency stop triggered")
    if severity == "CRITICAL":
        anomalies.append("Critical severity event")

    if not anomalies:
        return False, "NORMAL", "No anomalies detected"

    risk = "HIGH" if len(anomalies) >= 2 or severity == "CRITICAL" else "MEDIUM"
    return True, risk, " | ".join(anomalies)


def run_ml_detection(events):
    """Run Isolation Forest ML model"""
    if not ML_AVAILABLE or len(events) < 20:
        print(f"[ML] Using rule-based detection ({len(events)} events)")
        return run_rule_based(events)

    print(f"[ML] Running Isolation Forest on {len(events)} events...")
    X = prepare_features(events)

    model = IsolationForest(
        contamination=0.1,   # expect 10% anomalies
        random_state=42,
        n_estimators=100
    )
    predictions = model.fit_predict(X)    # -1 = anomaly, 1 = normal
    scores      = model.score_samples(X)  # lower = more anomalous

    results = []
    anomaly_count = 0

    for i, event in enumerate(events):
        is_anomaly_ml = predictions[i] == -1
        rule_anom, risk, reason = rule_based_anomaly(event)
        is_anomaly = is_anomaly_ml or rule_anom

        if is_anomaly:
            anomaly_count += 1
            risk_level = "CRITICAL" if (is_anomaly_ml and rule_anom) else risk

            results.append({
                "vehicle_id":    event["vehicle_id"],
                "event_type":    event["event_type"],
                "severity":      event["severity"],
                "speed_kmh":     event.get("speed_kmh"),
                "anomaly_score": float(scores[i]),
                "is_anomaly":    True,
                "risk_level":    risk_level,
                "reason":        reason,
            })

    print(f"[ML] Found {anomaly_count} anomalies out of {len(events)} events")
    return results


def run_rule_based(events):
    """Pure rule-based detection without ML"""
    results = []
    for event in events:
        is_anom, risk, reason = rule_based_anomaly(event)
        if is_anom:
            results.append({
                "vehicle_id":    event["vehicle_id"],
                "event_type":    event["event_type"],
                "severity":      event["severity"],
                "speed_kmh":     event.get("speed_kmh"),
                "anomaly_score": -1.0,
                "is_anomaly":    True,
                "risk_level":    risk,
                "reason":        reason,
            })
    return results


def save_anomalies(anomalies):
    """Save detected anomalies to database"""
    if not anomalies:
        print("[ML] No anomalies to save.")
        return
    conn = get_conn()
    with conn:
        with conn.cursor() as cur:
            # Clear old results
            cur.execute("DELETE FROM anomaly_scores")
            for a in anomalies[:100]:  # save top 100
                cur.execute("""
                    INSERT INTO anomaly_scores
                    (vehicle_id, event_type, severity, speed_kmh,
                     anomaly_score, is_anomaly, risk_level)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (
                    a["vehicle_id"], a["event_type"], a["severity"],
                    a["speed_kmh"], a["anomaly_score"],
                    a["is_anomaly"], a["risk_level"]
                ))
    conn.close()
    print(f"[ML] Saved {len(anomalies)} anomalies to database ✓")


def main():
    print("=" * 50)
    print("🤖 AV Security — ML Anomaly Detection")
    print("=" * 50)

    create_anomaly_table()
    events = fetch_events()

    if not events:
        print("[ML] No events found in database. Run producer.py first!")
        return

    print(f"[ML] Loaded {len(events)} events from PostgreSQL")
    anomalies = run_ml_detection(events)
    save_anomalies(anomalies)

    print("\n📊 TOP ANOMALIES DETECTED:")
    print("-" * 50)
    for a in anomalies[:10]:
        print(f"  🔴 {a['vehicle_id']} | {a['event_type']} | "
              f"Risk: {a['risk_level']} | Speed: {a.get('speed_kmh','?')}")
    print("=" * 50)
    print("✅ Done! Check analytics.html for visualization.")


if __name__ == "__main__":
    main()