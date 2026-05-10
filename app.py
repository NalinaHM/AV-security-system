"""
app.py — Flask API for AV Security Dashboard
=============================================
Reads from PostgreSQL and serves data to the live dashboard.

Run: python app.py
Then open: dashboard.html in your browser
"""

from flask import Flask, jsonify, render_template_string
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
CORS(app)  # Allow dashboard to access API

# ── DB Config ──────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     os.getenv("DB_PORT", "5433"),
    "dbname":   os.getenv("DB_NAME", "av_events_db"),
    "user":     os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres123"),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG)


# ── API Routes ─────────────────────────────────────────────────────────────

@app.route("/api/events")
def get_events():
    """Latest 50 AV events"""
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, vehicle_id, event_type, speed_kmh,
                       latitude, longitude, battery_pct, severity,
                       received_at::text as received_at
                FROM av_events
                ORDER BY received_at DESC
                LIMIT 50
            """)
            rows = cur.fetchall()
        conn.close()
        return jsonify({"status": "ok", "events": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/stats")
def get_stats():
    """Dashboard statistics"""
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Total events
            cur.execute("SELECT COUNT(*) as total FROM av_events")
            total = cur.fetchone()["total"]

            # Events by severity
            cur.execute("""
                SELECT severity, COUNT(*) as count
                FROM av_events
                GROUP BY severity
            """)
            severity = {r["severity"]: r["count"] for r in cur.fetchall()}

            # Events by vehicle
            cur.execute("""
                SELECT vehicle_id, COUNT(*) as count
                FROM av_events
                GROUP BY vehicle_id
                ORDER BY count DESC
                LIMIT 10
            """)
            vehicles = [dict(r) for r in cur.fetchall()]

            # Events by type
            cur.execute("""
                SELECT event_type, COUNT(*) as count
                FROM av_events
                GROUP BY event_type
                ORDER BY count DESC
            """)
            event_types = [dict(r) for r in cur.fetchall()]

            # Security violations
            cur.execute("SELECT COUNT(*) as total FROM security_audit")
            violations = cur.fetchone()["total"]

            # Recent events per minute (last 10 mins)
            cur.execute("""
                SELECT DATE_TRUNC('minute', received_at) as minute,
                       COUNT(*) as count
                FROM av_events
                WHERE received_at > NOW() - INTERVAL '10 minutes'
                GROUP BY minute
                ORDER BY minute
            """)
            timeline = [{"time": str(r["minute"]), "count": r["count"]}
                       for r in cur.fetchall()]

        conn.close()
        return jsonify({
            "status": "ok",
            "total_events": total,
            "severity": severity,
            "vehicles": vehicles,
            "event_types": event_types,
            "security_violations": violations,
            "timeline": timeline,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/security")
def get_security():
    """Security audit log"""
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, event_type, detail, logged_at::text as logged_at
                FROM security_audit
                ORDER BY logged_at DESC
                LIMIT 20
            """)
            rows = cur.fetchall()
        conn.close()
        return jsonify({"status": "ok", "violations": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "message": "AV Security API running"})


if __name__ == "__main__":
    print("🚀 AV Security Dashboard API running at http://localhost:5000")
    print("📊 Open dashboard.html in your browser")
    app.run(debug=True, port=5000, host="0.0.0.0")