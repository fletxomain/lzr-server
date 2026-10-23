import os
import json
import secrets
import hashlib
import hmac
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, Response, redirect, url_for, session, render_template_string, flash

app = Flask(__name__)
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LZR_DATA_DIR", os.path.join(ROOT, "data"))
DATA_FILE = os.path.join(DATA_DIR, "licenses.json")
HISTORY_FILE = os.path.join(DATA_DIR, "login_history.json")

ADMIN_USER = os.environ.get("LZR_ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.environ.get("LZR_ADMIN_PASSWORD", "")
SESSION_SECRET = os.environ.get("LZR_SESSION_SECRET", "")
KEY_PREFIX = os.environ.get("LZR_KEY_PREFIX", "fletxo_").strip() or "fletxo_"

os.makedirs(DATA_DIR, exist_ok=True)
if SESSION_SECRET:
    app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=1024 * 1024,
)

def now_ms():
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def utc_text(ms=None):
    if ms is None:
        dt = datetime.now(timezone.utc)
    else:
        dt = datetime.fromtimestamp(ms / 1000, timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def key_hash(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, type(default)) else default
    except (OSError, json.JSONDecodeError):
        return default

def write_json(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)

def load_data():
    return read_json(DATA_FILE, {})

def save_data(data):
    write_json(DATA_FILE, data)

def add_history(event, status, key="", device_id="", detail=""):
    history = read_json(HISTORY_FILE, [])
    if not isinstance(history, list):
        history = []
    # Never store the raw license key; only a short masked hint.
    hint = (key[:4] + "…" + key[-3:]) if len(key) > 9 else ("***" if key else "")
    history.append({
        "at": now_ms(),
        "event": str(event)[:40],
        "status": str(status)[:20],
        "license": hint,
        "device": str(device_id)[:120],
        "detail": str(detail)[:180],
    })
    write_json(HISTORY_FILE, history[-5000:])

def admin_configured():
    return bool(ADMIN_USER and ADMIN_PASSWORD and SESSION_SECRET)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not admin_configured():
            return Response(
                "Admin is not configured. Set LZR_ADMIN_USER, LZR_ADMIN_PASSWORD and LZR_SESSION_SECRET in Render Environment.",
                503, mimetype="text/plain"
            )
        if not session.get("admin_ok"):
            return redirect(url_for("admin_login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

LOGIN_STYLE = """
<style>
:root{--bg:#FCFBF4;--surface:#FFFFF0;--ink:#1E2022;--muted:#697170;--accent:#3F4E4F;--line:#e3e4da;--red:#a13c32;--green:#2e7051}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 18px 50px}header{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:18px clamp(16px,4vw,42px);border-bottom:1px solid var(--line);background:var(--surface)}
.brand{font-size:12px;font-weight:850;letter-spacing:.15em;color:var(--accent)}a{color:var(--accent);font-weight:700;text-decoration:none}
.card{background:var(--surface);border:1px solid var(--line);border-radius:17px;padding:20px;margin:14px 0;min-width:0}
h1{font-size:clamp(26px,4vw,36px);margin:0 0 7px}h2{font-size:19px;margin:0 0 13px}.muted{color:var(--muted)}label{font-size:13px;font-weight:750;display:block;margin:12px 0 6px}
input,select,button{font:inherit;border:1px solid var(--line);border-radius:9px;padding:10px 12px;background:#fff;color:var(--ink);max-width:100%}
button,.button{background:var(--accent);color:#fff;border:0;font-weight:750;cursor:pointer;display:inline-block;padding:10px 14px;border-radius:9px}
input{width:100%}.inline{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.inline input,.inline select{width:auto}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.num{font-size:29px;font-weight:850;margin-top:7px}.kicker{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-weight:800}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}.tablewrap{overflow-x:auto}
.pill{display:inline-block;padding:4px 8px;border-radius:99px;background:#e5eee7;color:var(--green);font-size:11px;font-weight:800}.pill.bad{background:#f8e7e2;color:var(--red)}
.msg{padding:11px 13px;border-radius:10px;background:#e9efe9;margin:12px 0;overflow-wrap:anywhere}.err{background:#f9e8e4;color:var(--red)}
.cal{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:5px}.dow{text-align:center;color:var(--muted);font-size:11px;padding:6px 0}.day{min-height:52px;border:1px solid var(--line);border-radius:9px;padding:6px;color:var(--ink);font-size:12px}.day.has{background:#e8eee8}.count{display:block;font-size:10px;color:var(--accent);font-weight:800;margin-top:5px}
@media(max-width:800px){.grid{grid-template-columns:1fr}.cols{grid-template-columns:1fr!important}}@media(max-width:500px){main{padding:20px 12px}.day{min-height:42px;padding:4px}}
</style>
"""

@app.get("/")
def home():
    return jsonify({
        "ok": True,
        "service": "LZR License API",
        "health": "/health",
        "login": "POST /login",
        "admin": "/admin",
        "admin_login": "/admin/login"
    })

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "LZR", "storage": "json"})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return jsonify({"success": False, "message": "POST JSON required"}), 405
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400
    body = request.get_json(silent=True) or {}
    key = str(body.get("key", "")).strip()
    device_id = str(body.get("device_id", "")).strip()
    if not key or not device_id or len(key) > 200 or len(device_id) > 200:
        add_history("login", "failed", key, device_id, "Missing/invalid input")
        return jsonify({"success": False, "message": "Key and device ID required"}), 400

    data = load_data()
    record = data.get(key_hash(key))
    if not record or record.get("active") is not True:
        add_history("login", "failed", key, device_id, "Invalid or inactive license")
        return jsonify({"success": False, "message": "Invalid or inactive license"}), 403

    expiry = int(record.get("expiresAt") or 0)
    if expiry and now_ms() > expiry:
        add_history("login", "failed", key, device_id, "License expired")
        return jsonify({"success": False, "message": "License expired"}), 403

    bound = str(record.get("deviceId") or "")
    if bound and not secrets.compare_digest(bound, device_id):
        add_history("login", "failed", key, device_id, "Device mismatch")
        return jsonify({"success": False, "message": "License bound to another device"}), 403

    if not bound:
        record["deviceId"] = device_id
        record["boundAt"] = now_ms()
        data[key_hash(key)] = record
        save_data(data)

    add_history("login", "success", key, device_id, "License accepted")
    return jsonify({"success": True, "message": "Login successful"})

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if not admin_configured():
        return Response(
            "Admin is not configured. In Render Environment set LZR_ADMIN_USER, LZR_ADMIN_PASSWORD and LZR_SESSION_SECRET, then redeploy.",
            503, mimetype="text/plain"
        )
    error = ""
    if request.method == "POST":
        username = str(request.form.get("username", ""))
        password = str(request.form.get("password", ""))
        if (hmac.compare_digest(username, ADMIN_USER)
                and hmac.compare_digest(password, ADMIN_PASSWORD)):
            session.clear()
            session.permanent = True
            session["admin_ok"] = True
            session["admin_user"] = ADMIN_USER
            return redirect(url_for("admin"))
        error = "Username or password is incorrect."
    return Response(render_template_string("""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CRAVAULT Admin Login</title>""" + LOGIN_STYLE + """</head><body><main style="max-width:440px;padding-top:8vh"><section class="card"><div class="brand">CRAVAULT PREMIUM AI ™</div><h1 style="margin-top:15px">Admin sign in</h1><p class="muted">Manage licenses and activity.</p>{% if error %}<div class="msg err">{{error}}</div>{% endif %}<form method="post" autocomplete="on"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><p style="margin-top:20px"><button type="submit">Sign in</button></p></form></section></main></body></html>""", error=error), mimetype="text/html")

@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    data = load_data()
    message = ""
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "create":
            try:
                amount = int(request.form.get("duration", "30"))
            except ValueError:
                amount = 30
            unit = request.form.get("unit", "days")
            if amount < 1 or amount > 876000:
                amount = 30
            if unit not in ("hours", "days", "lifetime"):
                unit = "days"
            if unit == "lifetime":
                expiry = 0
                duration_label = "Lifetime"
            else:
                multiplier = 3600000 if unit == "hours" else 86400000
                expiry = now_ms() + amount * multiplier
                duration_label = str(amount) + " " + unit
            key = KEY_PREFIX + secrets.token_urlsafe(18)
            data[key_hash(key)] = {
                "active": True, "expiresAt": expiry, "deviceId": "",
                "boundAt": 0, "createdAt": now_ms(),
                "duration": duration_label
            }
            save_data(data)
            add_history("key_created", "success", key, "", "Duration: " + duration_label)
            message = "New license key (copy now): " + key + " — " + duration_label
        elif action in ("toggle", "unbind"):
            rid = request.form.get("id", "")
            if rid in data:
                if action == "toggle":
                    data[rid]["active"] = not bool(data[rid].get("active", False))
                    detail = "License toggled"
                else:
                    data[rid]["deviceId"], data[rid]["boundAt"] = "", 0
                    detail = "Device unbound"
                save_data(data)
                add_history(action, "success", "", "", detail)
                message = "Updated successfully."
    history = read_json(HISTORY_FILE, [])
    history = list(reversed(history[-200:]))
    total = len(data)
    active = sum(1 for r in data.values() if r.get("active") is True)
    expired = sum(1 for r in data.values() if r.get("active") and r.get("expiresAt") and now_ms() > int(r.get("expiresAt") or 0))
    rows = []
    for rid, rec in sorted(data.items(), key=lambda item: int(item[1].get("createdAt") or 0), reverse=True):
        exp = int(rec.get("expiresAt") or 0)
        expiry_text = "Lifetime" if exp == 0 else utc_text(exp)
        rows.append({
            "id": rid,
            "short": rid[:12] + "…",
            "status": "Active" if rec.get("active") else "Disabled",
            "expiry": expiry_text,
            "device": "Bound" if rec.get("deviceId") else "Unbound",
            "created": utc_text(int(rec.get("createdAt") or now_ms())),
        })
    month = request.args.get("month", datetime.now(timezone.utc).strftime("%Y-%m"))
    try:
        month_dt = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
    except ValueError:
        month_dt = datetime.now(timezone.utc).replace(day=1)
        month = month_dt.strftime("%Y-%m")
    import calendar
    cal = calendar.Calendar(firstweekday=0)
    weeks = cal.monthdayscalendar(month_dt.year, month_dt.month)
    event_counts = {}
    for event in read_json(HISTORY_FILE, []):
        try:
            day = datetime.fromtimestamp(int(event["at"]) / 1000, timezone.utc).strftime("%Y-%m-%d")
            if day.startswith(month):
                event_counts[day] = event_counts.get(day, 0) + 1
        except (KeyError, TypeError, ValueError):
            pass
    prev_month = (month_dt.replace(day=1) - __import__("datetime").timedelta(days=1)).strftime("%Y-%m")
    if month_dt.month == 12:
        next_month = month_dt.replace(year=month_dt.year + 1, month=1).strftime("%Y-%m")
    else:
        next_month = month_dt.replace(month=month_dt.month + 1).strftime("%Y-%m")
    html = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CRAVAULT Admin</title>""" + LOGIN_STYLE + """</head><body>
<header><div class="brand">CRAVAULT PREMIUM AI ™ / ADMIN</div><a href="/admin/logout">Sign out ↗</a></header><main>
<div style="margin:10px 0 22px"><h1>Admin dashboard</h1><div class="muted">License management · login history · expiry calendar</div></div>
{% if message %}<div class="msg">{{message}}</div>{% endif %}
<div class="grid"><div class="card"><div class="kicker">Total licenses</div><div class="num">{{total}}</div></div><div class="card"><div class="kicker">Active licenses</div><div class="num">{{active}}</div></div><div class="card"><div class="kicker">Expired licenses</div><div class="num">{{expired}}</div></div></div>
<section class="card"><h2>Create license key</h2><form method="post" class="inline"><input type="hidden" name="action" value="create"><label for="duration" style="margin:0">Duration</label><input id="duration" name="duration" type="number" min="1" max="876000" value="24" style="width:105px"><select name="unit"><option value="hours" selected>Hours</option><option value="days">Days</option><option value="lifetime">Lifetime</option></select><button>Create key</button></form><p class="muted">New keys are shown only once. Copy the key immediately.</p></section>
<section class="card"><h2>License records</h2><div class="tablewrap"><table><thead><tr><th>Key hash</th><th>Status</th><th>Expiry (UTC)</th><th>Device</th><th>Created</th><th>Actions</th></tr></thead><tbody>
{% for r in rows %}<tr><td><code>{{r.short}}</code></td><td><span class="pill {% if r.status != 'Active' %}bad{% endif %}">{{r.status}}</span></td><td>{{r.expiry}}</td><td>{{r.device}}</td><td>{{r.created}}</td><td><form method="post" style="display:inline-block"><input type="hidden" name="action" value="toggle"><input type="hidden" name="id" value="{{r.id}}"><button type="submit">Toggle</button></form> <form method="post" style="display:inline-block"><input type="hidden" name="action" value="unbind"><input type="hidden" name="id" value="{{r.id}}"><button type="submit">Unbind</button></form></td></tr>{% endfor %}
{% if not rows %}<tr><td colspan="6" class="muted">No licenses yet.</td></tr>{% endif %}</tbody></table></div></section>
<section class="card"><div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap"><h2>Activity calendar</h2><div class="inline"><a href="/admin?month={{prev_month}}">← Previous</a><strong>{{month}}</strong><a href="/admin?month={{next_month}}">Next →</a></div></div><div class="cal">{% for d in ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'] %}<div class="dow">{{d}}</div>{% endfor %}{% for week in weeks %}{% for day in week %}{% if day == 0 %}<div></div>{% else %}{% set daykey = '%04d-%02d-%02d'|format(month_dt.year, month_dt.month, day) %}<div class="day {% if event_counts.get(daykey,0) %}has{% endif %}">{{day}}<span class="count">{% if event_counts.get(daykey,0) %}{{event_counts.get(daykey)}} event(s){% else %}&nbsp;{% endif %}</span></div>{% endif %}{% endfor %}{% endfor %}</div><p class="muted">Calendar shows recorded events; license expiry dates are listed in the table.</p></section>
<section class="card"><h2>Recent activity</h2><div class="tablewrap"><table><thead><tr><th>Time (UTC)</th><th>Event</th><th>License hint</th><th>Device</th><th>Status</th><th>Details</th></tr></thead><tbody>
{% for e in history %}<tr><td>{{utc_text(e.at)}}</td><td>{{e.event}}</td><td>{{e.license}}</td><td>{{e.device}}</td><td><span class="pill {% if e.status != 'success' %}bad{% endif %}">{{e.status}}</span></td><td>{{e.detail}}</td></tr>{% endfor %}
{% if not history %}<tr><td colspan="6" class="muted">No activity recorded yet.</td></tr>{% endif %}</tbody></table></div></section>
</main></body></html>"""
    return Response(render_template_string(
        html, message=message, total=total, active=active, expired=expired,
        rows=rows, history=history, month=month, weeks=weeks,
        event_counts=event_counts, month_dt=month_dt,
        prev_month=prev_month, next_month=next_month, utc_text=utc_text
    ), mimetype="text/html")

@app.errorhandler(500)
def internal_error(_error):
    return jsonify({"success": False, "message": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
