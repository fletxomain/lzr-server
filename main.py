import os, json, secrets, hashlib
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
ROOT = os.path.dirname(__file__)
DATA_DIR = os.path.join(ROOT, "data")
DATA_FILE = os.path.join(DATA_DIR, "licenses.json")
ADMIN_USER = os.environ.get("LZR_ADMIN_USER", "LZR")
ADMIN_PASSWORD = os.environ.get("LZR_ADMIN_PASSWORD", "FVMX3")
KEY_PREFIX = os.environ.get("LZR_KEY_PREFIX", "fletxo_")
API_SECRET = os.environ.get("LZR_API_SECRET", "")
os.makedirs(DATA_DIR, exist_ok=True)

def load_data():
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}

def save_data(data):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, DATA_FILE)

def now_ms():
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def key_hash(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not secrets.compare_digest(auth.username or "", ADMIN_USER) or not secrets.compare_digest(auth.password or "", ADMIN_PASSWORD):
            return Response("Admin login required", 401, {"WWW-Authenticate": 'Basic realm="LZR Admin"'})
        return fn(*args, **kwargs)
    return wrapper

@app.get("/")
def home():
    return jsonify({"ok": True, "service": "LZR License API", "health": "/health", "login": "POST /login", "admin": "/admin"})

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "LZR", "storage": "json"})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return jsonify({"success": False, "message": "POST JSON required"}), 405
    if API_SECRET and not secrets.compare_digest(request.headers.get("X-LZR-API-SECRET", ""), API_SECRET):
        return jsonify({"success": False, "message": "Unauthorized request"}), 401
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON body required"}), 400
    body = request.get_json(silent=True) or {}
    key = str(body.get("key", "")).strip()
    device_id = str(body.get("device_id", "")).strip()
    if not key or not device_id or len(key) > 200 or len(device_id) > 200:
        return jsonify({"success": False, "message": "Key and device ID required"}), 400
    data = load_data()
    record = data.get(key_hash(key))
    if not record or record.get("active") is not True:
        return jsonify({"success": False, "message": "Invalid or inactive license"}), 403
    expiry = int(record.get("expiresAt") or 0)
    if expiry and now_ms() > expiry:
        return jsonify({"success": False, "message": "License expired"}), 403
    bound = str(record.get("deviceId") or "")
    if bound and not secrets.compare_digest(bound, device_id):
        return jsonify({"success": False, "message": "License bound to another device"}), 403
    if not bound:
        record["deviceId"] = device_id
        record["boundAt"] = now_ms()
        data[key_hash(key)] = record
        save_data(data)
    return jsonify({"success": True, "message": "Login successful"})

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    data = load_data()
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
    rows = []
    for rid, rec in data.items():
        exp = int(rec.get("expiresAt") or 0)
        expiry_text = "Lifetime" if exp == 0 else datetime.fromtimestamp(exp / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        rows.append("<tr><td><code>"+rid[:12]+"…</code></td><td>"+("Active" if rec.get("active") else "Disabled")+"</td><td>"+expiry_text+"</td><td>"+("Bound" if rec.get("deviceId") else "Unbound")+"</td><td><form method='post'><input type='hidden' name='action' value='toggle'><input type='hidden' name='id' value='"+rid+"'><button>Toggle</button></form><form method='post'><input type='hidden' name='action' value='unbind'><input type='hidden' name='id' value='"+rid+"'><button>Unbind</button></form></td></tr>")
    msg = message.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    html = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>LZR Admin</title><style>body{font:16px system-ui;background:#111827;color:#f9fafb;padding:18px}main{max-width:900px;margin:auto}section{background:#1f2937;padding:16px;border-radius:12px;margin:14px 0}button,select{padding:9px;margin:4px;border-radius:6px}button{background:#2563eb;color:white;border:0}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:8px;border-bottom:1px solid #374151;text-align:left}code{overflow-wrap:anywhere}.msg{color:#86efac;overflow-wrap:anywhere}</style></head><body><main><h1>LZR Admin</h1><section><h2>Create license</h2><form method="post"><input type="hidden" name="action" value="create"><select name="days"><option value="1">1 day</option><option value="7">7 days</option><option value="30" selected>30 days</option><option value="365">365 days</option><option value="0">Lifetime</option></select><button>Create key</button></form><p class="msg">""" + msg + """</p></section><section><h2>License records</h2><div style="overflow-x:auto"><table><tr><th>Key hash</th><th>Status</th><th>Expiry</th><th>Device</th><th>Actions</th></tr>""" + "".join(rows) + """</table></div></section><p><a style="color:#93c5fd" href="/health">Health</a></p></main></body></html>"""
    return Response(html, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
