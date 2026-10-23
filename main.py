import os, json, secrets, hashlib, html, calendar
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, Response, redirect, url_for

app = Flask(__name__)
ROOT = os.path.dirname(__file__)
DATA_DIR = os.environ.get("LZR_DATA_DIR", os.path.join(ROOT, "data"))
DATA_FILE = os.path.join(DATA_DIR, "licenses.json")
HISTORY_FILE = os.path.join(DATA_DIR, "login_history.json")
ADMIN_USER = os.environ.get("LZR_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("LZR_ADMIN_PASSWORD", "")
KEY_PREFIX = os.environ.get("LZR_KEY_PREFIX", "fletxo_")
API_SECRET = os.environ.get("LZR_API_SECRET", "")
os.makedirs(DATA_DIR, exist_ok=True)

def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
            return obj if isinstance(obj, type(default)) else default
    except (OSError, json.JSONDecodeError):
        return default

def load_data():
    return read_json(DATA_FILE, {})

def save_data(data):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, DATA_FILE)

def load_history():
    return read_json(HISTORY_FILE, [])

def save_history(items):
    tmp = HISTORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items[-5000:], f, indent=2)
    os.replace(tmp, HISTORY_FILE)

def now_ms():
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def utc_iso(ms=None):
    if ms is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def key_hash(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def add_history(event, key="", device_id="", status="failed", details=""):
    items = load_history()
    items.append({
        "at": now_ms(),
        "event": str(event)[:40],
        "license_hint": (key[:4] + "…" + key[-3:]) if len(key) >= 8 else ("provided" if key else ""),
        "device_id": str(device_id)[:100],
        "status": status if status in ("success", "failed") else "failed",
        "details": str(details)[:180]
    })
    save_history(items)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        configured = bool(ADMIN_USER and ADMIN_PASSWORD)
        if (not configured or not auth
            or not secrets.compare_digest(auth.username or "", ADMIN_USER)
            or not secrets.compare_digest(auth.password or "", ADMIN_PASSWORD)):
            return Response("Admin login required. Configure LZR_ADMIN_USER and LZR_ADMIN_PASSWORD in Render.", 401,
                            {"WWW-Authenticate": 'Basic realm="CRAVAULT Admin"'})
        return fn(*args, **kwargs)
    return wrapper

def page_shell(title, body):
    return Response("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>"""+html.escape(title)+"""</title>
<style>
:root{--bg:#FCFBF4;--surface:#FFFFF0;--ink:#1E2022;--muted:#687170;--accent:#3F4E4F;--line:#e4e5db;--green:#2f7354;--red:#a84e3d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:20px clamp(15px,4vw,44px);border-bottom:1px solid var(--line);background:var(--surface)}
.brand{font-size:12px;letter-spacing:.15em;font-weight:850;color:var(--accent)}header a,.link{color:var(--accent);font-weight:750;text-decoration:none}
main{max-width:1250px;margin:0 auto;padding:28px clamp(14px,3vw,34px) 48px}.muted{color:var(--muted)}h1{font-size:clamp(26px,4vw,36px);margin:0 0 7px}h2{margin:0 0 12px;font-size:20px}
.top{display:flex;justify-content:space-between;align-items:end;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:18px 0}
.card{background:var(--surface);border:1px solid var(--line);border-radius:18px;padding:18px;min-width:0;box-shadow:0 10px 35px #1e202208}
.kicker{font-size:11px;color:var(--muted);font-weight:800;text-transform:uppercase;letter-spacing:.09em}.number{font-size:29px;font-weight:850;margin-top:7px}
.columns{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(290px,1fr);gap:15px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.tablewrap{overflow:auto}.pill{display:inline-block;padding:4px 8px;border-radius:99px;font-size:11px;font-weight:800;background:#e6efe8;color:var(--green)}.pill.bad{background:#f8e8e3;color:var(--red)}
input,select,button{font:inherit;border:1px solid var(--line);border-radius:9px;padding:9px 11px;background:white;color:var(--ink)}button{cursor:pointer;background:var(--accent);color:white;border:0;font-weight:750}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.notice{padding:12px 14px;border-radius:12px;background:#e8eee8;color:var(--accent);overflow-wrap:anywhere}
.calhead{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:15px 0}.cal{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:5px}.dow{text-align:center;font-size:10px;color:var(--muted);padding:5px 0}.day{min-height:52px;border:1px solid var(--line);border-radius:9px;padding:7px 5px;text-decoration:none;color:var(--ink);font-size:12px}.day.has{background:#e8eee8;border-color:#cbd8cd}.count{display:block;font-size:10px;color:var(--accent);margin-top:5px;font-weight:800}.empty{padding:22px;text-align:center;color:var(--muted)}
@media(max-width:900px){.columns{grid-template-columns:1fr}}@media(max-width:650px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.day{min-height:44px;padding:5px 3px}td,th{padding:9px 7px}}
</style></head><body><header><div class="brand">CRAVAULT PREMIUM AI ™ <span class="muted">/ ADMIN</span></div><nav><a href="/admin">Dashboard</a> &nbsp; <a href="/health">Health</a></nav></header>"""+body+"</body></html>", mimetype="text/html")

@app.get("/")
def home():
    return jsonify({"ok": True, "service": "LZR License API", "health": "/health", "login": "POST /login", "admin": "/admin"})

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "LZR", "storage": "json", "history": "enabled"})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return jsonify({"success": False, "message": "POST JSON required"}), 405
    if API_SECRET and not secrets.compare_digest(request.headers.get("X-LZR-API-SECRET", ""), API_SECRET):
        add_history("login", status="failed", details="API secret rejected")
        return jsonify({"success": False, "message": "Unauthorized request"}), 401
    if not request.is_json:
        add_history("login", status="failed", details="JSON body required")
        return jsonify({"success": False, "message": "JSON body required"}), 400
    body = request.get_json(silent=True) or {}
    key = str(body.get("key", "")).strip()
    device_id = str(body.get("device_id", "")).strip()
    if not key or not device_id or len(key) > 200 or len(device_id) > 200:
        add_history("login", key=key, device_id=device_id, status="failed", details="Key/device ID missing or too long")
        return jsonify({"success": False, "message": "Key and device ID required"}), 400

    data = load_data()
    record = data.get(key_hash(key))
    if not record or record.get("active") is not True:
        add_history("login", key=key, device_id=device_id, status="failed", details="Invalid or inactive license")
        return jsonify({"success": False, "message": "Invalid or inactive license"}), 403
    expiry = int(record.get("expiresAt") or 0)
    if expiry and now_ms() > expiry:
        add_history("login", key=key, device_id=device_id, status="failed", details="License expired")
        return jsonify({"success": False, "message": "License expired"}), 403
    bound = str(record.get("deviceId") or "")
    if bound and not secrets.compare_digest(bound, device_id):
        add_history("login", key=key, device_id=device_id, status="failed", details="License bound to another device")
        return jsonify({"success": False, "message": "License bound to another device"}), 403
    if not bound:
        record["deviceId"] = device_id
        record["boundAt"] = now_ms()
        data[key_hash(key)] = record
        save_data(data)
    add_history("login", key=key, device_id=device_id, status="success", details="Login successful")
    return jsonify({"success": True, "message": "Login successful"})

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    data = load_data()
    history = load_history()
    message = ""
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "create":
            try:
                days = int(request.form.get("days", "30"))
            except ValueError:
                days = 30
            if days < 0 or days > 36500:
                days = 30
            key = KEY_PREFIX + secrets.token_urlsafe(18)
            expiry = 0 if days == 0 else now_ms() + days * 86400000
            data[key_hash(key)] = {"active": True, "expiresAt": expiry, "deviceId": "", "boundAt": 0, "createdAt": now_ms()}
            save_data(data)
            message = "New key (copy now): " + key
        elif action in ("toggle", "unbind"):
            rid = request.form.get("id", "")
            if rid in data:
                if action == "toggle":
                    data[rid]["active"] = not bool(data[rid].get("active", False))
                else:
                    data[rid]["deviceId"], data[rid]["boundAt"] = "", 0
                save_data(data)
                message = "Updated."
        # Refresh state after an admin action.
        data = load_data()
        history = load_history()

    total = len(data)
    active = sum(1 for rec in data.values() if rec.get("active") is True)
    expired = sum(1 for rec in data.values() if int(rec.get("expiresAt") or 0) and now_ms() > int(rec.get("expiresAt") or 0))
    successes = sum(1 for e in history if e.get("status") == "success")
    failures = sum(1 for e in history if e.get("status") == "failed")

    date_filter = request.args.get("date", "")
    if len(date_filter) != 10 or date_filter[4:5] != "-" or date_filter[7:8] != "-":
        date_filter = ""
    if date_filter:
        try:
            datetime.strptime(date_filter, "%Y-%m-%d")
        except ValueError:
            date_filter = ""
    visible_history = [e for e in reversed(history) if not date_filter or datetime.fromtimestamp(int(e.get("at", 0))/1000, timezone.utc).strftime("%Y-%m-%d") == date_filter][:150]

    month = request.args.get("month", datetime.now(timezone.utc).strftime("%Y-%m"))
    try:
        month_dt = datetime.strptime(month, "%Y-%m").replace(day=1, tzinfo=timezone.utc)
        month = month_dt.strftime("%Y-%m")
    except ValueError:
        month_dt = datetime.now(timezone.utc).replace(day=1)
        month = month_dt.strftime("%Y-%m")
    cal = calendar.Calendar(firstweekday=0)
    counts = {}
    for event in history:
        d = datetime.fromtimestamp(int(event.get("at", 0))/1000, timezone.utc).strftime("%Y-%m-%d")
        if d.startswith(month):
            counts[d] = counts.get(d, 0) + 1

    def esc(v):
        return html.escape(str(v if v is not None else ""), quote=True)

    rows = []
    for event in visible_history:
        dt = utc_iso(int(event.get("at", 0)))
        status = event.get("status", "failed")
        rows.append("<tr><td>"+esc(dt)+"</td><td>"+esc(event.get("event", "login"))+"</td><td><code>"+esc(event.get("license_hint", ""))+"</code></td><td>"+esc(event.get("device_id", ""))+"</td><td><span class='pill "+("bad" if status != "success" else "")+"'>"+esc(status)+"</span></td><td>"+esc(event.get("details", ""))+"</td></tr>")
    if not rows:
        rows.append("<tr><td colspan='6' class='empty'>No login events recorded for this date.</td></tr>")

    license_rows = []
    for rid, rec in sorted(data.items(), key=lambda item: int(item[1].get("createdAt") or 0), reverse=True):
        exp = int(rec.get("expiresAt") or 0)
        expiry_text = "Lifetime" if exp == 0 else utc_iso(exp)
        state = "Active" if rec.get("active") else "Disabled"
        bound = "Bound" if rec.get("deviceId") else "Unbound"
        license_rows.append("<tr><td><code>"+esc(rid[:12])+"…</code></td><td>"+esc(state)+"</td><td>"+esc(expiry_text)+"</td><td>"+esc(bound)+"</td><td><form method='post'><input type='hidden' name='action' value='toggle'><input type='hidden' name='id' value='"+esc(rid)+"'><button>Toggle</button></form><form method='post'><input type='hidden' name='action' value='unbind'><input type='hidden' name='id' value='"+esc(rid)+"'><button class='secondary'>Unbind</button></form></td></tr>")
    if not license_rows:
        license_rows.append("<tr><td colspan='5' class='empty'>No licenses yet.</td></tr>")

    prev_month = (month_dt.replace(day=1) - __import__('datetime').timedelta(days=1)).strftime("%Y-%m")
    if month_dt.month == 12:
        next_month = month_dt.replace(year=month_dt.year+1, month=1).strftime("%Y-%m")
    else:
        next_month = month_dt.replace(month=month_dt.month+1).strftime("%Y-%m")
    calendar_cells = []
    for week in cal.monthdayscalendar(month_dt.year, month_dt.month):
        for day in week:
            if day == 0:
                calendar_cells.append("<div></div>")
            else:
                day_key = "%04d-%02d-%02d" % (month_dt.year, month_dt.month, day)
                count = counts.get(day_key, 0)
                calendar_cells.append("<a class='day "+("has" if count else "")+"' href='/admin?date="+day_key+"&month="+month+"'>"+str(day)+"<span class='count'>"+(str(count)+" event"+("s" if count != 1 else "") if count else "&nbsp;")+"</span></a>")
    message_html = "<div class='notice'>"+esc(message)+"</div>" if message else ""
    date_value = esc(date_filter)
    body = """<main>
<div class="top"><div><h1>Admin dashboard</h1><div class="muted">License management, login audit history and calendar.</div></div><div class="muted">Secure admin area · UTC timestamps</div></div>
"""+message_html+"""
<section class="grid">
<div class="card"><div class="kicker">Total licenses</div><div class="number">"""+str(total)+"""</div></div>
<div class="card"><div class="kicker">Active licenses</div><div class="number">"""+str(active)+"""</div></div>
<div class="card"><div class="kicker">Expired licenses</div><div class="number">"""+str(expired)+"""</div></div>
<div class="card"><div class="kicker">Login events</div><div class="number">"""+str(len(history))+"""</div><div class="muted">"""+str(successes)+""" success · """+str(failures)+""" failed</div></div>
</section>
<section class="card" style="margin-bottom:16px"><h2>Create license</h2><form method="post" class="filters"><input type="hidden" name="action" value="create"><select name="days"><option value="1">1 day</option><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option><option value="365">365 days</option><option value="0">Lifetime</option></select><button>Create license key</button></form><div class="muted">New key is shown once after creation. Store it securely.</div></section>
<section class="columns">
<div class="card"><h2>Login history</h2><div class="muted">Most recent 150 events. Raw license keys are never stored in history.</div>
<form method="get" class="filters"><input type="date" name="date" value=\""""+date_value+""""><input type="hidden" name="month" value=\""""+esc(month)+""""><button>Filter</button><a class="link" href="/admin?month="""+esc(month)+"""">Clear</a></form>
<div class="tablewrap"><table><thead><tr><th>Date / time (UTC)</th><th>Event</th><th>License hint</th><th>Device ID</th><th>Status</th><th>Details</th></tr></thead><tbody>"""+''.join(rows)+"""</tbody></table></div></div>
<div class="card"><h2>Activity calendar</h2><div class="muted">Select a date to filter login history.</div>
<div class="calhead"><a class="link" href="/admin?month="""+prev_month+"""">← Previous</a><strong>"""+month_dt.strftime("%B %Y")+"""</strong><a class="link" href="/admin?month="""+next_month+"""">Next →</a></div>
<div class="cal">"""+''.join("<div class='dow'>"+d+"</div>" for d in ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"])+''.join(calendar_cells)+"""</div>
<p class="muted" style="font-size:12px;margin-top:14px">Calendar counts recorded login events. License expiry dates are shown in the license table.</p></div>
</section>
<section class="card" style="margin-top:16px"><h2>License records</h2><div class="tablewrap"><table><thead><tr><th>License hash</th><th>Status</th><th>Expiry</th><th>Device</th><th>Actions</th></tr></thead><tbody>"""+''.join(license_rows)+"""</tbody></table></div></section>
</main><style>.secondary{background:#687170}form{display:inline-flex;gap:4px;align-items:center}form.filters{display:flex}.filters .link{padding:8px}@media(max-width:650px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}</style>"""
    return page_shell("CRAVAULT Admin", body)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
