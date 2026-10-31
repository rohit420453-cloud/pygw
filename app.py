import os, hmac, hashlib, secrets, base64, imaplib, email, re, html, threading, ipaddress, socket
from datetime import datetime, timedelta, timezone
from email import policy
from urllib.parse import urlparse, quote
import psycopg2, psycopg2.extras, requests
from cryptography.fernet import Fernet
from flask import Flask, request, session, redirect, g, jsonify, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ["APP_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("INSECURE_COOKIES") != "1")
F = Fernet(base64.urlsafe_b64encode(hashlib.sha256(os.environ["APP_KEY"].encode()).digest()))
TTL = int(os.environ.get("ORDER_TTL", 300))
BASE = os.environ.get("BASE_URL", "").rstrip("/")
now = lambda: datetime.now(timezone.utc)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,email TEXT UNIQUE,pass_hash TEXT,api_key TEXT UNIQUE,
 imap_host TEXT DEFAULT 'imap.gmail.com',imap_user TEXT,imap_pass_enc TEXT,sender_filter TEXT,upi_id TEXT,webhook_url TEXT,
 auto_confirm BOOLEAN DEFAULT FALSE,last_check TIMESTAMPTZ,created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS orders(id SERIAL PRIMARY KEY,order_id TEXT UNIQUE,user_id INT,amount NUMERIC(10,2),payable NUMERIC(10,2),
 status TEXT DEFAULT 'pending',utr TEXT,customer_name TEXT,redirect_url TEXT,webhook_url TEXT,webhook_ok BOOLEAN DEFAULT FALSE,
 webhook_tries INT DEFAULT 0,created_at TIMESTAMPTZ DEFAULT now(),expires_at TIMESTAMPTZ,paid_at TIMESTAMPTZ,UNIQUE(user_id,utr));
CREATE UNIQUE INDEX IF NOT EXISTS open_amt ON orders(user_id,payable) WHERE status IN('pending','detected','review');
CREATE TABLE IF NOT EXISTS seen_emails(user_id INT,msg_id TEXT,PRIMARY KEY(user_id,msg_id));
CREATE TABLE IF NOT EXISTS audit(id SERIAL PRIMARY KEY,user_id INT,event TEXT,detail TEXT,at TIMESTAMPTZ DEFAULT now());
"""

def db():
    if "db" not in g:
        g.db = psycopg2.connect(os.environ["DATABASE_URL"], cursor_factory=psycopg2.extras.RealDictCursor)
    return g.db

@app.teardown_appcontext
def _close(e):
    d = g.pop("db", None)
    if d: d.close()

def q(sql, a=(), one=False):
    try:
        with db().cursor() as c:
            c.execute(sql, a)
            r = (c.fetchone() if one else c.fetchall()) if c.description else None
        db().commit()
        return r
    except Exception:
        db().rollback(); raise

def audit(uid, ev, detail=""):
    q("INSERT INTO audit(user_id,event,detail) VALUES(%s,%s,%s)", (uid, ev, str(detail)[:500]))

def enc(s): return F.encrypt(s.encode()).decode()
def dec(s):
    try: return F.decrypt(s.encode()).decode()
    except Exception: return ""

def safe_url(u):
    try:
        p = urlparse(u or "")
        if p.scheme not in ("http", "https") or not p.hostname: return None
        ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
        return None if (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local) else u
    except Exception:
        return None

def inp(k):
    j = request.get_json(silent=True) or {}
    return j.get(k) or request.values.get(k)

def api_user():
    k = request.headers.get("X-Api-Key")
    m = re.match(r"Bearer\s+(\S+)", request.headers.get("Authorization", ""))
    k = k or (m.group(1) if m else None) or inp("api_key")
    return q("SELECT * FROM users WHERE api_key=%s", (k,), one=True) if k else None

def me():
    return q("SELECT * FROM users WHERE id=%s", (session["uid"],), one=True) if session.get("uid") else None

def csrf():
    session.setdefault("csrf", secrets.token_hex(16)); return session["csrf"]

@app.before_request
def _csrf():
    if request.method == "POST" and not request.path.startswith("/api/"):
        if not hmac.compare_digest(session.get("csrf", "x"), request.form.get("csrf", "")):
            return "Bad CSRF token", 400
app.jinja_env.globals["csrf"] = csrf

def upi_intent(upi, oid, amt):
    return f"upi://pay?pa={quote(upi or '')}&pn=Merchant&tr={oid}&tn={oid}&am={amt:.2f}&cu=INR"

def expire_old():
    q("UPDATE orders SET status='expired' WHERE status='pending' AND expires_at<now()")

def create_order(u, amt, redir, hook, name):
    expire_old()
    oid = "gw_" + secrets.token_hex(4).upper()
    for i in range(100):
        p = round(amt + i / 100, 2)
        try:
            q("INSERT INTO orders(order_id,user_id,amount,payable,customer_name,redirect_url,webhook_url,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
              (oid, u["id"], amt, p, (name or "")[:120], safe_url(redir), safe_url(hook), now() + timedelta(seconds=TTL)))
            audit(u["id"], "order_created", f"{oid} {p}")
            return {"order_id": oid, "amount": f"{amt:.2f}", "payable_amount": f"{p:.2f}",
                    "checkout_url": f"{BASE}/pay/{oid}", "upi_intent": upi_intent(u["upi_id"], oid, p),
                    "created_at": now().isoformat(), "expires_at": (now() + timedelta(seconds=TTL)).isoformat()}
        except psycopg2.errors.UniqueViolation:
            continue
    return None

def send_webhook(order_pk):
    o = q("SELECT o.*,u.api_key,u.webhook_url AS uhook FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=%s", (order_pk,), one=True)
    url = safe_url(o["webhook_url"] or o["uhook"])
    if not url:
        q("UPDATE orders SET webhook_ok=TRUE WHERE id=%s", (order_pk,)); return
    body = ('{"event":"payment.success","order_id":"%s","amount":"%s","status":"success","utr":"%s","payment_time":"%s","timestamp":%d}'
            % (o["order_id"], o["payable"], o["utr"] or "", o["paid_at"].isoformat(), int(now().timestamp())))
    sig = hmac.new(o["api_key"].encode(), body.encode(), hashlib.sha256).hexdigest()
    try:
        r = requests.post(url, data=body, timeout=5, allow_redirects=False,
                          headers={"Content-Type": "application/json", "X-FamGateway-Event": "payment.success", "X-FamGateway-Signature": sig})
        ok = r.status_code == 200
    except Exception:
        ok = False
    q("UPDATE orders SET webhook_ok=%s,webhook_tries=webhook_tries+1 WHERE id=%s", (ok, order_pk))

def finalize(o, utr):
    r = q("UPDATE orders SET status='success',utr=COALESCE(%s,utr),paid_at=now() WHERE id=%s AND status<>'success' RETURNING id", (utr, o["id"]), one=True)
    if r:
        audit(o["user_id"], "verified", o["order_id"]); send_webhook(o["id"])

def body_text(msg):
    part = msg.get_body(preferencelist=("plain", "html"))
    t = part.get_content() if part else ""
    return html.unescape(re.sub(r"<[^>]+>", " ", t))

def check_user(u):
    try:
        M = imaplib.IMAP4_SSL(u["imap_host"], 993, timeout=20)
        M.login(u["imap_user"], dec(u["imap_pass_enc"])); M.select("INBOX", readonly=True)
        since = (now() - timedelta(days=1)).strftime("%d-%b-%Y")
        _, d = M.search(None, "SINCE", since, "FROM", '"%s"' % u["sender_filter"].replace('"', ""))
        for n in d[0].split():
            _, data = M.fetch(n, "(RFC822)")
            msg = email.message_from_bytes(data[0][1], policy=policy.default)
            if re.search(r"dkim=fail|spf=fail", str(msg.get("Authentication-Results", "")), re.I): continue
            mid = str(msg.get("Message-ID") or hashlib.sha256(data[0][1]).hexdigest())
            if not q("INSERT INTO seen_emails VALUES(%s,%s) ON CONFLICT DO NOTHING RETURNING 1", (u["id"], mid), one=True): continue
            t = body_text(msg)
            if not re.search(r"received|credited|paid you", t, re.I): continue
            m = re.search(r"(?:₹|Rs\.?|INR)\s*([\d,]+(?:\.\d{1,2})?)", t, re.I)
            if not m: continue
            amt = round(float(m.group(1).replace(",", "")), 2)
            tm = re.search(r"(?:UTR|Ref(?:erence)?(?: No)?|Txn(?: ID)?|Transaction ID)[\s:#-]*([A-Za-z0-9]{8,})", t, re.I)
            utr = tm.group(1) if tm else None
            c1 = q("SELECT * FROM orders WHERE user_id=%s AND payable=%s AND status='pending' AND expires_at>=now()", (u["id"], amt))
            if len(c1) == 1:
                try:
                    q("UPDATE orders SET status='detected',utr=%s WHERE id=%s", (utr, c1[0]["id"]))
                except psycopg2.errors.UniqueViolation:
                    audit(u["id"], "duplicate_utr", utr); continue
                audit(u["id"], "detected", c1[0]["order_id"])
                if u["auto_confirm"]: finalize(c1[0], utr)
                continue
            c2 = q("SELECT * FROM orders WHERE user_id=%s AND payable=%s AND status='expired' AND expires_at>=now()-interval '30 minutes'", (u["id"], amt))
            if len(c2) == 1:
                try:
                    q("UPDATE orders SET status='review',utr=%s WHERE id=%s", (utr, c2[0]["id"])); audit(u["id"], "late_payment", c2[0]["order_id"])
                except psycopg2.errors.UniqueViolation: pass
            else:
                audit(u["id"], "unmatched_or_ambiguous", f"amt={amt} utr={utr}")
        M.logout()
    except Exception as e:
        audit(u["id"], "imap_fail", repr(e))

def maybe_check(uid):
    """Throttled (20s) email check. Atomic so parallel polls don't repeat it."""
    u = q("UPDATE users SET last_check=now() WHERE id=%s AND imap_pass_enc IS NOT NULL AND sender_filter<>'' AND (last_check IS NULL OR last_check<now()-interval '20 seconds') RETURNING *", (uid,), one=True)
    if u:
        with app.app_context():
            pass
        threading.Thread(target=lambda: _bg(u), daemon=True).start()

def _bg(u):
    with app.app_context():
        expire_old(); check_user(u)

STYLE = """<meta name=viewport content="width=device-width,initial-scale=1"><style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;margin:0;padding:16px}
.w{max-width:900px;margin:auto}.c{background:#1e293b;padding:16px;border-radius:12px;margin-bottom:14px}input,button{padding:9px;margin:4px 0;border-radius:8px;border:0;width:100%;box-sizing:border-box}
button{background:#2563eb;color:#fff;cursor:pointer;width:auto}code{word-break:break-all;color:#7dd3fc}.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px}
.g div{background:#334155;padding:10px;border-radius:8px;text-align:center}table{width:100%;font-size:13px;border-collapse:collapse}td,th{padding:6px;border-bottom:1px solid #334155;text-align:left}.t{overflow-x:auto}a{color:#94a3b8}</style>"""

LOGIN = STYLE + """<div class=w style="max-width:340px;margin-top:10vh"><form class=c method=post><h2>Gateway Login</h2><p style=color:#f87171>{{err}}</p>
<input type=hidden name=csrf value="{{csrf()}}"><input name=email type=email placeholder=Email required><input name=password type=password placeholder=Password required>
<button name=act value=login>Login</button> <button name=act value=register style="background:#475569">Create account</button></form></div>"""

DASH = STYLE + """<div class=w><h2>Dashboard <a href=/logout style="font-size:14px">logout</a></h2><p>{{msg}}</p>
<div class=c><b>API key</b><br><code>{{u.api_key}}</code><form method=post><input type=hidden name=csrf value="{{csrf()}}"><input type=hidden name=action value=newkey><button>Regenerate</button></form></div>
<div class=c><b>Email (IMAP) settings</b><form method=post><input type=hidden name=csrf value="{{csrf()}}"><input type=hidden name=action value=save>
<input name=imap_host value="{{u.imap_host or ''}}" placeholder="IMAP host (imap.gmail.com)"><input name=imap_user value="{{u.imap_user or ''}}" placeholder="Gmail address">
<input name=imap_pass type=password placeholder="{{'App password saved (leave blank to keep)' if u.imap_pass_enc else 'Gmail App Password'}}">
<input name=sender_filter value="{{u.sender_filter or ''}}" placeholder="FamPay sender email (required)"><input name=upi_id value="{{u.upi_id or ''}}" placeholder="Your UPI ID">
<input name=webhook_url value="{{u.webhook_url or ''}}" placeholder="Webhook URL (optional)">
<label><input type=checkbox name=auto_confirm value=1 style="width:auto" {{'checked' if u.auto_confirm}}> Treat unique matching email as verified (otherwise confirm manually)</label><br><button>Save</button></form></div>
<div class="c g">{% for k in ['pending','detected','success','expired','review'] %}<div><b>{{cnt.get(k,0)}}</b><br>{{k}}</div>{% endfor %}</div>
<div class="c t"><table><tr><th>Order<th>Amount<th>Status<th>UTR<th>Created (UTC)<th>Expires<th></tr>{% for o in orders %}
<tr><td>{{o.order_id}}<td>₹{{o.payable}}<td>{{o.status}}<td>{{o.utr or ''}}<td>{{o.created_at.strftime('%d %b %H:%M:%S')}}<td>{{o.expires_at.strftime('%H:%M:%S')}}<td>
{% if o.status in ['detected','review'] %}<form method=post><input type=hidden name=csrf value="{{csrf()}}"><input type=hidden name=action value=verify><input type=hidden name=oid value="{{o.order_id}}"><button>Verify</button></form>{% endif %}</tr>{% endfor %}</table></div></div>"""

PAY = STYLE + """<div class=w style="max-width:340px;margin-top:6vh"><div class=c style=text-align:center><h2>Pay ₹{{o.payable}}</h2><p>Pay exactly this amount</p>
<div id=q style="background:#fff;padding:10px;display:inline-block;border-radius:8px"></div><h1 id=t>--:--</h1><p id=m>Waiting for payment…</p>
<a href="{{link}}" style="display:block;background:#2563eb;color:#fff;padding:10px;border-radius:8px;text-decoration:none">Pay with UPI app</a></div></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>new QRCode(document.getElementById('q'),{text:{{link|tojson}},width:200,height:200});
var id={{o.order_id|tojson}},redir={{(o.redirect_url or '')|tojson}},end=0,off=0;
function tick(){var l=Math.max(0,Math.floor((end-Date.now()-off)/1000));t.textContent=String(Math.floor(l/60)).padStart(2,'0')+':'+String(l%60).padStart(2,'0')}
async function poll(){try{var r=await (await fetch('/api/checkout-status?order_id='+id)).json();
end=new Date(r.expires_at).getTime();off=Date.now()-new Date(r.server_time).getTime();
if(r.status=='success'){m.textContent='Payment verified ✔ UTR '+(r.utr||'');if(redir)setTimeout(()=>location=redir,2000);return}
if(r.status=='detected'||r.status=='review')m.textContent='PAYMENT DETECTED — VERIFICATION PENDING';
if(r.status=='expired'){m.textContent='Expired. Create a new order.';return}}catch(e){}setTimeout(poll,3000)}
poll();setInterval(tick,500);</script>"""

@app.route("/", methods=["GET", "POST"])
def index():
    err = ""
    if request.method == "POST":
        e, p, act = request.form.get("email", "").strip().lower(), request.form.get("password", ""), request.form.get("act")
        if act == "register":
            if not re.match(r"[^@\s]+@[^@\s]+\.\w+$", e) or len(p) < 8: err = "Valid email and 8+ char password required"
            else:
                try:
                    r = q("INSERT INTO users(email,pass_hash,api_key) VALUES(%s,%s,%s) RETURNING id", (e, generate_password_hash(p), "gw_" + secrets.token_hex(20)), one=True)
                    session.clear(); session["uid"] = r["id"]; return redirect("/dashboard")
                except psycopg2.errors.UniqueViolation: err = "Email already registered"
        else:
            u = q("SELECT * FROM users WHERE email=%s", (e,), one=True)
            if u and check_password_hash(u["pass_hash"], p):
                session.clear(); session["uid"] = u["id"]; return redirect("/dashboard")
            err = "Wrong email or password"
    return render_template_string(LOGIN, err=err)

@app.route("/logout")
def logout():
    session.clear(); return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    u = me()
    if not u: return redirect("/")
    msg = ""
    if request.method == "POST":
        a, f = request.form.get("action"), request.form
        if a == "save":
            pw = f.get("imap_pass", "")
            q("UPDATE users SET imap_host=%s,imap_user=%s,imap_pass_enc=%s,sender_filter=%s,upi_id=%s,webhook_url=%s,auto_confirm=%s WHERE id=%s",
              (f.get("imap_host", "").strip(), f.get("imap_user", "").strip(), enc(pw) if pw else u["imap_pass_enc"], f.get("sender_filter", "").strip(),
               f.get("upi_id", "").strip(), safe_url(f.get("webhook_url")), bool(f.get("auto_confirm")), u["id"]))
            audit(u["id"], "settings_saved"); msg = "Saved"
        elif a == "newkey":
            q("UPDATE users SET api_key=%s WHERE id=%s", ("gw_" + secrets.token_hex(20), u["id"])); audit(u["id"], "api_key_regenerated"); msg = "New API key created"
        elif a == "verify":
            o = q("SELECT * FROM orders WHERE order_id=%s AND user_id=%s AND status IN('detected','review')", (f.get("oid"), u["id"]), one=True)
            if o: finalize(o, None); msg = "Marked verified"
        u = me()
    expire_old()
    cnt = {r["status"]: r["c"] for r in q("SELECT status,COUNT(*) c FROM orders WHERE user_id=%s GROUP BY status", (u["id"],))}
    orders = q("SELECT * FROM orders WHERE user_id=%s ORDER BY id DESC LIMIT 50", (u["id"],))
    return render_template_string(DASH, u=u, msg=msg, cnt=cnt, orders=orders)

@app.route("/pay/<oid>")
def pay(oid):
    o = q("SELECT o.*,u.upi_id FROM orders o JOIN users u ON u.id=o.user_id WHERE order_id=%s", (oid,), one=True)
    if not o: return "Order not found", 404
    return render_template_string(PAY, o=o, link=upi_intent(o["upi_id"], oid, float(o["payable"])))

@app.route("/api/create-order", methods=["POST", "GET"])
def api_create():
    u = api_user()
    if not u: return jsonify(status="error", message="Invalid API key"), 401
    if not u["upi_id"]: return jsonify(status="error", message="Set UPI ID in dashboard"), 422
    try: a = float(inp("amount"))
    except Exception: a = 0
    if not 1 <= a <= 100000: return jsonify(status="error", message="Invalid amount"), 422
    d = create_order(u, a, inp("redirect_url"), inp("webhook_url"), inp("customer_name"))
    return (jsonify(status="success", data=d) if d else (jsonify(status="error", message="Too many open orders for this amount"), 429))

@app.route("/api/checkout-status")
def api_status():
    expire_old()
    o = q("SELECT order_id,user_id,payable,status,utr,expires_at FROM orders WHERE order_id=%s", (request.args.get("order_id", ""),), one=True)
    if not o: return jsonify(status="not_found"), 404
    if o["status"] in ("pending", "expired"): maybe_check(o["user_id"])
    r = {"status": o["status"], "order_id": o["order_id"], "amount": str(o["payable"]), "expires_at": o["expires_at"].isoformat(), "server_time": now().isoformat()}
    if o["status"] == "success": r["utr"] = o["utr"]
    return jsonify(r)

@app.route("/api/verify-order")
def api_verify():
    expire_old(); u = api_user()
    if not u: return jsonify(status="error", message="Invalid API key"), 401
    o = q("SELECT order_id,payable,status,utr,created_at,expires_at,paid_at FROM orders WHERE order_id=%s AND user_id=%s", (request.args.get("order_id", ""), u["id"]), one=True)
    if not o: return jsonify(status="not_found"), 404
    return jsonify(status="success", data={k: (v.isoformat() if hasattr(v, "isoformat") else str(v) if k == "payable" else v) for k, v in o.items()})

@app.route("/ping")
def ping():
    """Call every 5 min from UptimeRobot: keeps server awake + checks all inboxes + retries webhooks."""
    if os.environ.get("PING_TOKEN") and request.args.get("t") != os.environ["PING_TOKEN"]: return "no", 403
    expire_old()
    for u in q("SELECT id FROM users WHERE imap_pass_enc IS NOT NULL"): maybe_check(u["id"])
    for r in q("SELECT id FROM orders WHERE status='success' AND NOT webhook_ok AND webhook_tries<3"): send_webhook(r["id"])
    return "ok"

with app.app_context():
    q(SCHEMA)
