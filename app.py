from __future__ import annotations

import html
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt
from flask import Flask, jsonify, request, send_from_directory, session


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = (BASE_DIR / ".." / "frontend").resolve()
DB_PATH = (BASE_DIR / "database.db").resolve()


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-secret-key-change-me")

with app.app_context():
    init_db()


SQLI_REGEX = re.compile(
    r"(?i)\b(select|union|insert|update|delete|drop|alter|create|exec|execute)\b|(--|\bor\b\s+1\s*=\s*1|/\*|\*/|;)"
)
XSS_REGEX = re.compile(
    r"(?i)(<\s*script\b|onerror\s*=|onload\s*=|javascript:|<\s*img\b|<\s*svg\b|<\s*iframe\b)"
)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_client_ip() -> str:
    # If running behind a proxy, a real deployment should validate/strip this header.
    xfwd = request.headers.get("X-Forwarded-For")
    if xfwd:
        return xfwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              email TEXT,
              password_hash TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS insecure_comments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT NOT NULL,
              ip TEXT NOT NULL,
              username TEXT NOT NULL,
              comment TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secure_comments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT NOT NULL,
              ip TEXT NOT NULL,
              username TEXT NOT NULL,
              comment TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attack_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT NOT NULL,
              ip TEXT NOT NULL,
              payload TEXT NOT NULL,
              attack_type TEXT NOT NULL
            );
            """
        )

        # Seed a default user for demos (bcrypt-hashed).
        # This makes SQLi bypass and secure login reproducible on a fresh DB.
        existing = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not existing:
            default_pw = "admin12345".encode("utf-8")
            default_hash = bcrypt.hashpw(default_pw, bcrypt.gensalt(rounds=12)).decode("utf-8")
            conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                ("admin", "admin@example.com", default_hash, utc_now_iso()),
            )


def log_attack(payload: str, attack_type: str) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO attack_logs (timestamp, ip, payload, attack_type) VALUES (?, ?, ?, ?)",
            (utc_now_iso(), get_client_ip(), payload, attack_type),
        )


def classify_and_log_suspicious(payload: str) -> Optional[str]:
    """
    Log *suspicious* input centrally for the admin dashboard.
    This is not a WAF; it's an educational telemetry feature.
    """
    s = payload or ""
    if SQLI_REGEX.search(s):
        log_attack(s, "SQLi")
        return "SQLi"
    if XSS_REGEX.search(s):
        log_attack(s, "XSS")
        return "XSS"
    return None


def json_body() -> dict[str, Any]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return {}
    return data


def hash_password(password: str) -> str:
    pw = password.encode("utf-8")
    hashed = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


@dataclass
class AuthUser:
    id: int
    username: str


def current_user() -> Optional[AuthUser]:
    uid = session.get("user_id")
    uname = session.get("username")
    if isinstance(uid, int) and isinstance(uname, str):
        return AuthUser(id=uid, username=uname)
    return None


def require_login() -> AuthUser:
    user = current_user()
    if not user:
        raise PermissionError("Not authenticated")
    return user


@app.get("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def serve_static(filename: str):
    # Simple static serving for demo (HTML/CSS/JS).
    return send_from_directory(FRONTEND_DIR, filename)


# ----------------------------
# INSECURE (for demonstration)
# ----------------------------


@app.post("/api/insecure/login")
def insecure_login():
    """
    INSECURE: This endpoint is intentionally vulnerable to SQL injection.

    WHY vulnerable:
    - It uses string concatenation to build a SQL query from untrusted input.
    - It treats "any returned row" as authenticated (no password verification),
      making SQLi bypass obvious for learning purposes.
    """
    data = json_body()
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))  # intentionally unused (see above)
    email = str(data.get("email", ""))

    # Log suspicious payloads (telemetry)
    classify_and_log_suspicious(username)
    classify_and_log_suspicious(password)
    classify_and_log_suspicious(email)

    # INSECURE: string concatenation (SQL injection vulnerability)
    query = f"SELECT id, username, password_hash FROM users WHERE username = '{username}'"

    try:
        with get_db() as conn:
            row = conn.execute(query).fetchone()
    except sqlite3.Error as e:
        # If attacker breaks SQL syntax, show error (insecure behavior).
        return jsonify(
            {
                "ok": False,
                "message": "SQL error (insecure endpoint leaks DB error).",
                "error": str(e),
                "insecure_query": query,
            }
        ), 400

    if row:
        session["user_id"] = int(row["id"])
        session["username"] = str(row["username"])
        return jsonify(
            {
                "ok": True,
                "message": "Login successful (INSECURE). Authentication can be bypassed via SQL injection.",
                "user": {"id": int(row["id"]), "username": str(row["username"])},
                "insecure_query": query,
                "note": "This endpoint is intentionally insecure for education. Do not copy into production.",
            }
        )

    return jsonify({"ok": False, "message": "Login failed (INSECURE).", "insecure_query": query}), 401


@app.post("/api/insecure/comment")
def insecure_comment():
    """
    INSECURE: This endpoint is intentionally vulnerable to stored XSS.

    WHY vulnerable:
    - It stores and returns comments exactly as provided (no sanitization).
    - When the frontend renders with innerHTML, scripts/handlers can execute.
    """
    data = json_body()
    username = str(data.get("username", "anonymous"))
    comment = str(data.get("comment", ""))

    classify_and_log_suspicious(username)
    classify_and_log_suspicious(comment)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO insecure_comments (timestamp, ip, username, comment) VALUES (?, ?, ?, ?)",
            (utc_now_iso(), get_client_ip(), username, comment),
        )
        rows = conn.execute(
            "SELECT id, timestamp, ip, username, comment FROM insecure_comments ORDER BY id DESC LIMIT 20"
        ).fetchall()

    return jsonify(
        {
            "ok": True,
            "message": "Comment stored (INSECURE). Output is not sanitized; rendering with innerHTML can execute scripts.",
            "comments": [dict(r) for r in rows],  # contains raw HTML/JS payloads
        }
    )


@app.get("/api/insecure/comments")
def insecure_comments():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, ip, username, comment FROM insecure_comments ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return jsonify({"ok": True, "comments": [dict(r) for r in rows]})


# ------------
# SECURE APIs
# ------------


@app.post("/api/secure/register")
def secure_register():
    data = json_body()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))

    classify_and_log_suspicious(username)
    classify_and_log_suspicious(email)

    if not USERNAME_RE.fullmatch(username):
        return jsonify({"ok": False, "error": "Invalid username."}), 400
    if email and not EMAIL_RE.fullmatch(email):
        return jsonify({"ok": False, "error": "Invalid email."}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400

    pw_hash = hash_password(password)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, pw_hash, utc_now_iso()),
            )
            user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "User already exists."}), 409

    session["user_id"] = int(user_id)
    session["username"] = username
    return jsonify({"ok": True, "message": "Registered successfully.", "user": {"id": int(user_id), "username": username}})


@app.post("/api/secure/login")
def secure_login():
    data = json_body()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    classify_and_log_suspicious(username)

    if not USERNAME_RE.fullmatch(username):
        return jsonify({"ok": False, "error": "Invalid username."}), 400

    with get_db() as conn:
        row = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()

    if not row:
        return jsonify({"ok": False, "error": "Invalid credentials."}), 401

    if not verify_password(password, str(row["password_hash"])):
        return jsonify({"ok": False, "error": "Invalid credentials."}), 401

    session["user_id"] = int(row["id"])
    session["username"] = str(row["username"])
    return jsonify({"ok": True, "message": "Login successful (SECURE).", "user": {"id": int(row["id"]), "username": str(row["username"])}})


@app.post("/api/secure/logout")
def secure_logout():
    session.clear()
    return jsonify({"ok": True, "message": "Logged out."})


@app.get("/api/secure/me")
def secure_me():
    user = current_user()
    if not user:
        return jsonify({"ok": True, "authenticated": False, "user": None})
    return jsonify({"ok": True, "authenticated": True, "user": {"id": user.id, "username": user.username}})


@app.post("/api/secure/comment")
def secure_comment():
    """
    SECURE: protects against XSS via output escaping + server-side validation.

    HOW protected:
    - Validates input length and username format.
    - Stores raw comment (for auditability), but escapes when returning to clients.
    - Frontend should render via textContent (defense-in-depth).
    """
    try:
        user = require_login()
    except PermissionError:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    data = json_body()
    comment = str(data.get("comment", "")).strip()

    classify_and_log_suspicious(comment)

    if len(comment) == 0 or len(comment) > 1000:
        return jsonify({"ok": False, "error": "Comment must be 1-1000 characters."}), 400

    # Basic "dangerous pattern" checks (educational; not a replacement for proper encoding)
    # If XSS-like patterns exist, they were already logged by classify_and_log_suspicious().
    # We still allow storing (for education/auditing), but always return escaped output.

    with get_db() as conn:
        conn.execute(
            "INSERT INTO secure_comments (timestamp, ip, username, comment) VALUES (?, ?, ?, ?)",
            (utc_now_iso(), get_client_ip(), user.username, comment),
        )
        rows = conn.execute(
            "SELECT id, timestamp, ip, username, comment FROM secure_comments ORDER BY id DESC LIMIT 20"
        ).fetchall()

    escaped = []
    for r in rows:
        d = dict(r)
        d["comment"] = html.escape(str(d["comment"]))
        d["username"] = html.escape(str(d["username"]))
        escaped.append(d)

    return jsonify({"ok": True, "message": "Comment stored (SECURE). Returned data is HTML-escaped.", "comments": escaped})


@app.get("/api/secure/comments")
def secure_comments():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, ip, username, comment FROM secure_comments ORDER BY id DESC LIMIT 20"
        ).fetchall()
    escaped = []
    for r in rows:
        d = dict(r)
        d["comment"] = html.escape(str(d["comment"]))
        d["username"] = html.escape(str(d["username"]))
        escaped.append(d)
    return jsonify({"ok": True, "comments": escaped})


# -------------------
# Admin / attack logs
# -------------------


@app.get("/api/admin/logs")
def admin_logs():
    try:
        limit = int(request.args.get("limit", "200"))
    except ValueError:
        limit = 200
    limit = max(1, min(limit, 1000))

    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, ip, payload, attack_type FROM attack_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return jsonify({"ok": True, "logs": [dict(r) for r in rows]})


@app.get("/api/admin/stats")
def admin_stats():
    try:
        window_hours = int(request.args.get("window_hours", "24"))
    except ValueError:
        window_hours = 24
    window_hours = max(1, min(window_hours, 24 * 30))

    # SQLite stores ISO timestamps (UTC). ISO strings compare lexicographically.
    since_iso = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat(timespec="seconds")

    with get_db() as conn:
        sqli = conn.execute(
            "SELECT COUNT(*) AS c FROM attack_logs WHERE attack_type = 'SQLi' AND timestamp >= ?",
            (since_iso,),
        ).fetchone()["c"]
        xss = conn.execute(
            "SELECT COUNT(*) AS c FROM attack_logs WHERE attack_type = 'XSS' AND timestamp >= ?",
            (since_iso,),
        ).fetchone()["c"]

    return jsonify({"ok": True, "window_hours": window_hours, "stats": {"sqli": int(sqli), "xss": int(xss)}})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)

