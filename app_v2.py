"""
app_v2.py — Flask API v2 with Anomaly Detection routes
=======================================================
Replace your existing app.py with this file.
Run: python app_v2.py
"""

from flask import Flask, jsonify
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     os.getenv("DB_PORT", "5433"),
    "dbname":   os.getenv("DB_NAME", "av_events_db"),
    "user":     os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres123"),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG)


# ── Original routes ────────────────────────────────────────────────────────

@app.route("/api/events")
def get_events():
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, vehicle_id, event_type, speed_kmh,
                       latitude, longitude, battery_pct, severity,
                       received_at::text as received_at
                FROM av_events ORDER BY received_at DESC LIMIT 50
            """)
            rows = cur.fetchall()
        conn.close()
        return jsonify({"status": "ok", "events": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/stats")
def get_stats():
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) as total FROM av_events")
            total = cur.fetchone()["total"]

            cur.execute("SELECT severity, COUNT(*) as count FROM av_events GROUP BY severity")
            severity = {r["severity"]: r["count"] for r in cur.fetchall()}

            cur.execute("""
                SELECT vehicle_id, COUNT(*) as count FROM av_events
                GROUP BY vehicle_id ORDER BY count DESC LIMIT 10
            """)
            vehicles = [dict(r) for r in cur.fetchall()]

            cur.execute("""
                SELECT event_type, COUNT(*) as count FROM av_events
                GROUP BY event_type ORDER BY count DESC
            """)
            event_types = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT COUNT(*) as total FROM security_audit")
            violations = cur.fetchone()["total"]

            # Events per hour (last 24 hours)
            cur.execute("""
                SELECT DATE_TRUNC('hour', received_at) as hour,
                       COUNT(*) as count
                FROM av_events
                WHERE received_at > NOW() - INTERVAL '24 hours'
                GROUP BY hour ORDER BY hour
            """)
            hourly = [{"hour": str(r["hour"]), "count": r["count"]}
                     for r in cur.fetchall()]

        conn.close()
        return jsonify({
            "status": "ok",
            "total_events": total,
            "severity": severity,
            "vehicles": vehicles,
            "event_types": event_types,
            "security_violations": violations,
            "hourly_timeline": hourly,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/security")
def get_security():
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, event_type, detail, logged_at::text as logged_at
                FROM security_audit ORDER BY logged_at DESC LIMIT 20
            """)
            rows = cur.fetchall()
        conn.close()
        return jsonify({"status": "ok", "violations": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── NEW: Anomaly Detection routes ──────────────────────────────────────────

@app.route("/api/anomalies")
def get_anomalies():
    """Return ML-detected anomalies"""
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Check if table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'anomaly_scores'
                )
            """)
            exists = cur.fetchone()["exists"]

            if not exists:
                return jsonify({"status": "ok", "anomalies": [],
                               "message": "Run anomaly_detection.py first"})

            cur.execute("""
                SELECT vehicle_id, event_type, severity, speed_kmh,
                       anomaly_score, risk_level,
                       detected_at::text as detected_at
                FROM anomaly_scores
                WHERE is_anomaly = true
                ORDER BY detected_at DESC
                LIMIT 50
            """)
            rows = cur.fetchall()

            # Count by risk level
            cur.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM anomaly_scores WHERE is_anomaly = true
                GROUP BY risk_level
            """)
            risk_counts = {r["risk_level"]: r["count"] for r in cur.fetchall()}

            # Count by vehicle
            cur.execute("""
                SELECT vehicle_id, COUNT(*) as count
                FROM anomaly_scores WHERE is_anomaly = true
                GROUP BY vehicle_id ORDER BY count DESC
            """)
            by_vehicle = [dict(r) for r in cur.fetchall()]

        conn.close()
        return jsonify({
            "status": "ok",
            "anomalies": [dict(r) for r in rows],
            "risk_counts": risk_counts,
            "by_vehicle": by_vehicle,
            "total": len(rows),
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/speed-distribution")
def speed_distribution():
    """Speed histogram data for charts"""
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    CASE
                        WHEN speed_kmh < 20  THEN '0-20'
                        WHEN speed_kmh < 40  THEN '20-40'
                        WHEN speed_kmh < 60  THEN '40-60'
                        WHEN speed_kmh < 80  THEN '60-80'
                        WHEN speed_kmh < 100 THEN '80-100'
                        WHEN speed_kmh < 120 THEN '100-120'
                        ELSE '120+'
                    END as range,
                    COUNT(*) as count
                FROM av_events
                WHERE speed_kmh IS NOT NULL
                GROUP BY range ORDER BY range
            """)
            rows = cur.fetchall()
        conn.close()
        return jsonify({"status": "ok", "distribution": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "message": "AV Security API v2 running"})


if __name__ == "__main__":
    print("🚀 AV Security Dashboard API v2 — http://localhost:5000")
    print("📊 Open analytics.html for charts & ML results")
    app.run(debug=True, port=5000, host="0.0.0.0")