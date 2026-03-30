"""
S3M NAC Policy Engine — FastAPI
================================
FreeRADIUS rlm_rest modülü üzerinden çağrılan merkezi politika motoru.

Endpoints:
  POST /auth           — PAP/CHAP + MAB kimlik doğrulama (Redis rate-limiting)
  POST /authorize      — Dinamik VLAN atama (radgroupreply → Tunnel-*)
  POST /accounting     — Oturum verisi kaydetme (PostgreSQL + Redis cache)
  GET  /users          — Kullanıcı listesi ve durum bilgisi
  GET  /sessions/active — Aktif oturumlar (Redis)
  GET  /health         — Sağlık kontrolü
  GET  /dashboard      — Web arayüzü
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import redis
import psycopg2
import psycopg2.extras
import os
import bcrypt
import json
import time
import uuid

# ──────────────────────────────────────────────
# Konfigürasyon (environment variables)
# ──────────────────────────────────────────────
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "nac_postgres")
POSTGRES_DB   = os.getenv("POSTGRES_DB", "nac_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "s3m_admin")
POSTGRES_PASS = os.getenv("POSTGRES_PASSWORD", "cokgizlisifre123")

REDIS_HOST    = os.getenv("REDIS_HOST", "nac_redis")
REDIS_PORT    = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB      = int(os.getenv("REDIS_DB", "0"))

FAIL_LIMIT         = int(os.getenv("FAIL_LIMIT", "3"))
FAIL_BLOCK_SECONDS = int(os.getenv("FAIL_BLOCK_SECONDS", "30"))

# ──────────────────────────────────────────────
# Redis & PostgreSQL bağlantı yardımcıları
# ──────────────────────────────────────────────
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)


def get_db():
    """Her istek için yeni bir PostgreSQL bağlantısı oluşturur."""
    return psycopg2.connect(
        host=POSTGRES_HOST,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASS,
    )


# ──────────────────────────────────────────────
# FastAPI uygulama tanımı
# ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup/shutdown lifecycle."""
    yield


app = FastAPI(
    title="S3M NAC Policy Engine",
    description="FreeRADIUS rlm_rest entegrasyonlu NAC politika motoru",
    version="2.0.0",
    lifespan=lifespan,
)
templates = Jinja2Templates(directory="templates")


# ══════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════
@app.get("/health")
async def health():
    """Basit sağlık kontrolü — Docker healthcheck için."""
    return {"status": "healthy"}


# ══════════════════════════════════════════════
#  POST /auth — Kimlik Doğrulama
#  PAP/CHAP (şifre tabanlı) + MAB (MAC tabanlı)
# ══════════════════════════════════════════════
@app.post("/auth")
async def authenticate(request: Request):
    """
    FreeRADIUS rlm_rest → /auth

    İki senaryo:
    1. PAP/CHAP: username + password gönderilir → bcrypt doğrulama
    2. MAB: password boş, mac_address / Calling-Station-Id dolu → MAC lookup

    Rate-limiting: FAIL_LIMIT başarısız denemeden sonra FAIL_BLOCK_SECONDS
    saniyelik blok uygulanır (Redis counter).
    """
    data = await request.json()
    username     = (data.get("username") or "").strip()
    password_raw = (data.get("password") or "").strip()
    mac_address  = (data.get("mac_address") or "").strip().upper()

    if not username:
        return JSONResponse({"Status": "Reject", "Reply-Message": "Missing username"})

    # ── Rate-limit kontrolü ──
    fail_key = f"fail:{username}"
    fail_count = r.get(fail_key)
    if fail_count and int(fail_count) >= FAIL_LIMIT:
        ttl = r.ttl(fail_key)
        return JSONResponse({
            "Status": "Reject",
            "Reply-Message": f"Rate limited — try again in {ttl}s",
        })

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # ── MAB akışı (şifre yoksa, MAC adresi varsa) ──
        if not password_raw and mac_address:
            return _mab_auth(cur, username, mac_address)

        # ── PAP/CHAP akışı (şifre tabanlı) ──
        if password_raw:
            return _pap_auth(cur, username, password_raw, fail_key)

        # Hiçbir bilgi yok → reject
        return JSONResponse({"Status": "Reject", "Reply-Message": "No credentials"})

    finally:
        cur.close()
        conn.close()


def _mab_auth(cur, username: str, mac: str) -> JSONResponse:
    """
    MAC Authentication Bypass (MAB)
    Yazıcı, IP telefon gibi 802.1X desteklemeyen cihazlar için.
    MAC adresi users tablosunda kayıtlıysa → Accept
    Değilse → Reject (varsayılan politika: reject)
    """
    # MAC formatını normalize et (AA:BB:CC:DD:EE:FF → büyük harf)
    mac_normalized = mac.upper().replace("-", ":").replace(".", ":")

    cur.execute(
        "SELECT username, role, is_active FROM users WHERE UPPER(mac_address) = %s",
        (mac_normalized,),
    )
    row = cur.fetchone()

    if row and row["is_active"]:
        return JSONResponse({
            "Status": "Accept",
            "Reply-Message": f"MAB: Device authenticated as {row['username']}",
            "User-Name": row["username"],  # Gerçek username'e map et
        })

    # Bilinmeyen MAC → varsayılan politika: REJECT
    return JSONResponse({
        "Status": "Reject",
        "Reply-Message": f"MAB: Unknown or inactive MAC {mac_normalized}",
    })


def _pap_auth(cur, username: str, password_raw: str, fail_key: str) -> JSONResponse:
    """
    PAP/CHAP — bcrypt ile hash doğrulama.
    Plaintext asla kabul edilmez.
    """
    cur.execute(
        "SELECT password, is_active FROM users WHERE username = %s",
        (username,),
    )
    user = cur.fetchone()

    if not user:
        _increment_fail(fail_key)
        return JSONResponse({"Status": "Reject", "Reply-Message": "User not found"})

    if not user["is_active"]:
        return JSONResponse({"Status": "Reject", "Reply-Message": "Account disabled"})

    # bcrypt doğrulama
    try:
        password_bytes = password_raw.encode("utf-8")
        hashed_bytes   = user["password"].encode("utf-8")
        if bcrypt.checkpw(password_bytes, hashed_bytes):
            # Başarılı → sayaç sıfırla
            r.delete(fail_key)
            return JSONResponse({"Status": "Accept"})
    except Exception:
        pass  # Hash formatı hatalıysa → reject olarak devam

    # Başarısız → sayaç artır
    _increment_fail(fail_key)
    return JSONResponse({"Status": "Reject", "Reply-Message": "Invalid password"})


def _increment_fail(fail_key: str):
    """Redis'teki başarısız giriş sayacını artır."""
    r.incr(fail_key)
    r.expire(fail_key, FAIL_BLOCK_SECONDS)


# ══════════════════════════════════════════════
#  POST /authorize — Yetkilendirme (VLAN Atama)
# ══════════════════════════════════════════════
@app.post("/authorize")
async def authorize(request: Request):
    """
    FreeRADIUS rlm_rest → /authorize (post-auth aşamasında çağrılır)

    Kullanıcının grubunu radusergroup tablosundan bulur,
    radgroupreply tablosundan VLAN atribütlerini çeker.

    Dönen atribütler:
      Tunnel-Type, Tunnel-Medium-Type, Tunnel-Private-Group-Id
    """
    data = await request.json()
    username = (data.get("username") or "").strip()

    if not username:
        return JSONResponse({
            "Status": "Accept",
            "Tunnel-Type": "VLAN",
            "Tunnel-Medium-Type": "IEEE-802",
            "Tunnel-Private-Group-Id": "30",  # guest fallback
        })

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # ① Kullanıcının ait olduğu grubu bul
        cur.execute(
            """SELECT groupname FROM radusergroup
               WHERE username = %s
               ORDER BY priority ASC LIMIT 1""",
            (username,),
        )
        group_row = cur.fetchone()

        # MAB ile gelen cihazlar users tablosundaki role üzerinden de eşleşebilir
        if not group_row:
            cur.execute(
                "SELECT role FROM users WHERE username = %s OR UPPER(mac_address) = %s",
                (username, username.upper()),
            )
            user_row = cur.fetchone()
            group_name = user_row["role"] if user_row else "guest"
        else:
            group_name = group_row["groupname"]

        # ② Grubun VLAN atribütlerini çek
        cur.execute(
            """SELECT attribute, value FROM radgroupreply
               WHERE groupname = %s""",
            (group_name,),
        )
        attrs = cur.fetchall()

        # Sonucu oluştur
        result = {"Status": "Accept"}
        for attr in attrs:
            result[attr["attribute"]] = attr["value"]

        # Eğer hiç atribüt bulunamadıysa guest VLAN fallback
        if len(result) == 1:
            result.update({
                "Tunnel-Type": "VLAN",
                "Tunnel-Medium-Type": "IEEE-802",
                "Tunnel-Private-Group-Id": "30",
            })

        return JSONResponse(result)

    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════
#  POST /accounting — Oturum Verisi Kaydetme
# ══════════════════════════════════════════════
@app.post("/accounting")
async def accounting(request: Request):
    """
    FreeRADIUS rlm_rest → /accounting

    Accounting-Start  → radacct INSERT + Redis SET
    Interim-Update    → radacct UPDATE + Redis refresh
    Accounting-Stop   → radacct UPDATE (stop time) + Redis DELETE

    Redis cache: session:{acct_session_id} → JSON (hızlı sorgulama için)
    """
    data = await request.json()
    username      = (data.get("username") or "").strip()
    status_type   = (data.get("status") or "").strip()
    session_id    = (data.get("session_id") or "").strip()
    nas_ip        = (data.get("nas_ip") or "0.0.0.0").strip()
    nas_port      = (data.get("nas_port") or "").strip()
    input_octets  = int(data.get("input_octets") or 0)
    output_octets = int(data.get("output_octets") or 0)
    session_time  = int(data.get("session_time") or 0)

    if not session_id:
        session_id = str(uuid.uuid4())[:16]

    acct_unique = f"{username}_{session_id}"
    redis_key   = f"session:{session_id}"
    now         = time.strftime("%Y-%m-%d %H:%M:%S%z")

    conn = get_db()
    cur = conn.cursor()

    try:
        if status_type == "Start":
            # ── Accounting-Start ──
            cur.execute(
                """INSERT INTO radacct
                   (acctsessionid, acctuniqueid, username, nasipaddress,
                    nasportid, acctstarttime, acctupdatetime,
                    acctinputoctets, acctoutputoctets, callingstationid)
                   VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), 0, 0, '')
                   ON CONFLICT DO NOTHING""",
                (session_id, acct_unique, username, nas_ip, nas_port),
            )
            conn.commit()

            # Redis cache
            r.set(redis_key, json.dumps({
                "username": username,
                "session_id": session_id,
                "nas_ip": nas_ip,
                "start_time": now,
                "input_octets": 0,
                "output_octets": 0,
                "session_time": 0,
            }))

        elif status_type == "Interim-Update":
            # ── Interim-Update ──
            cur.execute(
                """UPDATE radacct SET
                     acctupdatetime   = NOW(),
                     acctsessiontime  = %s,
                     acctinputoctets  = %s,
                     acctoutputoctets = %s
                   WHERE acctsessionid = %s AND username = %s""",
                (session_time, input_octets, output_octets, session_id, username),
            )
            conn.commit()

            # Redis cache güncelle
            existing = r.get(redis_key)
            if existing:
                sess = json.loads(existing)
                sess.update({
                    "input_octets": input_octets,
                    "output_octets": output_octets,
                    "session_time": session_time,
                })
                r.set(redis_key, json.dumps(sess))

        elif status_type == "Stop":
            # ── Accounting-Stop ──
            cur.execute(
                """UPDATE radacct SET
                     acctstoptime     = NOW(),
                     acctupdatetime   = NOW(),
                     acctsessiontime  = %s,
                     acctinputoctets  = %s,
                     acctoutputoctets = %s,
                     acctterminatecause = 'User-Request'
                   WHERE acctsessionid = %s AND username = %s""",
                (session_time, input_octets, output_octets, session_id, username),
            )
            conn.commit()

            # Redis cache sil
            r.delete(redis_key)

        return JSONResponse({"Status": "Success"})

    except Exception as e:
        conn.rollback()
        return JSONResponse({"Status": "Error", "Message": str(e)}, status_code=500)

    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════
#  POST /users — Yeni Kullanıcı Ekleme
# ══════════════════════════════════════════════
@app.post("/users")
async def create_user(request: Request):
    """
    Dashboard üzerinden yeni kullanıcı (admin, employee, guest) ekler.
    Kullanıcı şifresi PostgreSQL'in pgcrypto eklentisi ile bcrypt() kullanılarak hashlenir.
    """
    data = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "guest").strip()
    mac_address = (data.get("mac_address") or "").strip()

    if not username or not password:
        return JSONResponse({"status": "error", "message": "Kullanıcı adı ve şifre zorunludur."}, status_code=400)

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            """INSERT INTO users (username, password, mac_address, role, is_active)
               VALUES (%s, crypt(%s, gen_salt('bf')), %s, %s, TRUE)""",
            (username, password, mac_address, role)
        )
        cur.execute(
            """INSERT INTO radusergroup (username, groupname, priority)
               VALUES (%s, %s, 1)""",
            (username, role)
        )
        cur.execute(
            """INSERT INTO radcheck (username, attribute, op, value)
               VALUES (%s, 'Cleartext-Password', ':=', %s)""",
            (username, password)
        )
        conn.commit()
        return {"status": "success", "message": f"Kullanıcı {username} başarıyla oluşturuldu"}
    except Exception as e:
        conn.rollback()
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════
#  GET /users — Kullanıcı Listesi
# ══════════════════════════════════════════════
@app.get("/users")
async def list_users():
    """
    Tüm kullanıcıları listeler (users + radusergroup join).
    Dönen alanlar: username, mac_address, is_active, role, group
    """
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        cur.execute(
            """SELECT u.username, u.mac_address, u.is_active, u.role,
                      COALESCE(g.groupname, u.role) AS "group"
               FROM users u
               LEFT JOIN radusergroup g ON u.username = g.username
               ORDER BY u.id"""
        )
        users = cur.fetchall()
        return JSONResponse({"users": users})

    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════
#  GET /sessions/active — Aktif Oturumlar (Redis)
# ══════════════════════════════════════════════
@app.get("/sessions/active")
async def active_sessions():
    """
    Redis'teki session:* anahtarlarını tarayarak aktif oturumları döner.
    (Hızlı sorgulama için PostgreSQL'e gitmeden Redis cache kullanılır.)
    """
    sessions = []
    for key in r.scan_iter("session:*"):
        raw = r.get(key)
        if raw:
            try:
                sess = json.loads(raw)
                sessions.append(sess)
            except json.JSONDecodeError:
                continue

    return JSONResponse({"active_sessions": sessions, "count": len(sessions)})


# ══════════════════════════════════════════════
#  DASHBOARD — Web Arayüzü
# ══════════════════════════════════════════════
@app.get("/dashboard")
async def dashboard(request: Request):
    """Jinja2 destekli dashboard sayfası."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        cur.execute(
            """SELECT u.id, u.username, u.is_active, u.mac_address,
                      u.role, COALESCE(g.groupname, u.role) AS groupname
               FROM users u
               LEFT JOIN radusergroup g ON u.username = g.username
               ORDER BY u.id"""
        )
        users = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    # Redis'ten aktif oturumlar
    active = []
    for key in r.scan_iter("session:*"):
        raw = r.get(key)
        if raw:
            try:
                sess = json.loads(raw)
                active.append(sess)
            except json.JSONDecodeError:
                continue

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "users": users,
        "active_sessions": active,
    })


# ══════════════════════════════════════════════
#  CANLI SİMÜLASYON (Dashboard için)
# ══════════════════════════════════════════════
@app.post("/simulate/{action}")
async def simulate(action: str, data: dict):
    """Dashboard simülasyon endpoint'i."""
    user = data.get("username", "")
    sid  = f"SIM_{user}_{int(time.time())}"

    if action == "connect":
        r.set(f"session:{sid}", json.dumps({
            "username": user,
            "session_id": sid,
            "nas_ip": "127.0.0.1",
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "input_octets": 0,
            "output_octets": 0,
            "session_time": 0,
        }))
    else:
        # Kullanıcıya ait tüm simülasyon oturumlarını sil
        for key in r.scan_iter(f"session:SIM_{user}_*"):
            r.delete(key)

    return {"status": "ok"}


# ══════════════════════════════════════════════
#  DASHBOARD YARDIMCI ENDPOINT'LER
#  (Tüm özellikleri dashboard üzerinden test etme)
# ══════════════════════════════════════════════

@app.get("/rate-limit/{username}")
async def rate_limit_status(username: str):
    """
    Belirtilen kullanıcının rate-limit durumunu döner.
    Dashboard'da rate-limiting'in çalıştığını göstermek için.
    """
    fail_key = f"fail:{username}"
    count = r.get(fail_key)
    ttl = r.ttl(fail_key)
    return {
        "username": username,
        "fail_count": int(count) if count else 0,
        "limit": FAIL_LIMIT,
        "blocked": int(count) >= FAIL_LIMIT if count else False,
        "ttl_seconds": ttl if ttl > 0 else 0,
    }


@app.get("/rate-limit-all")
async def rate_limit_all():
    """Tüm rate-limit anahtarlarını listeler."""
    entries = []
    for key in r.scan_iter("fail:*"):
        username = key.split(":", 1)[1]
        count = r.get(key)
        ttl = r.ttl(key)
        entries.append({
            "username": username,
            "fail_count": int(count) if count else 0,
            "blocked": int(count) >= FAIL_LIMIT if count else False,
            "ttl_seconds": ttl if ttl > 0 else 0,
        })
    return {"rate_limits": entries, "limit_threshold": FAIL_LIMIT, "block_seconds": FAIL_BLOCK_SECONDS}


@app.get("/accounting/history")
async def accounting_history():
    """
    radacct tablosundaki son 20 accounting kaydını döner.
    Dashboard'da accounting'in çalıştığını göstermek için.
    """
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        cur.execute(
            """SELECT acctsessionid, username, nasipaddress::text as nas_ip,
                      acctstarttime, acctstoptime, acctsessiontime,
                      acctinputoctets, acctoutputoctets, acctterminatecause
               FROM radacct
               ORDER BY radacctid DESC
               LIMIT 20"""
        )
        records = cur.fetchall()

        # datetime nesnelerini stringe çevir
        for rec in records:
            for key in ['acctstarttime', 'acctstoptime']:
                if rec[key]:
                    rec[key] = str(rec[key])

        return {"records": records, "count": len(records)}
    finally:
        cur.close()
        conn.close()


@app.post("/dashboard/auth-test")
async def dashboard_auth_test(request: Request):
    """
    Dashboard'dan auth testi — sonuçları doğrudan gösterir.
    PAP ve MAB testlerini dashboard üzerinden yapmak için.
    """
    data = await request.json()
    test_type = data.get("type", "pap")  # "pap" veya "mab"

    if test_type == "mab":
        # MAB testi: sadece MAC adresi gönderilir
        auth_payload = {
            "username": data.get("mac", ""),
            "mac_address": data.get("mac", ""),
        }
    else:
        # PAP testi: username + password
        auth_payload = {
            "username": data.get("username", ""),
            "password": data.get("password", ""),
        }

    # Doğrudan /auth endpoint'ini çağır (internal)
    from starlette.testclient import TestClient
    # Internal olarak auth fonksiyonunu çağırıyoruz
    fake_username = auth_payload.get("username", "")
    fake_password = auth_payload.get("password", "")
    fake_mac = auth_payload.get("mac_address", "")

    # ── Rate-limit kontrolü ──
    fail_key = f"fail:{fake_username}"
    fail_count = r.get(fail_key)

    if fail_count and int(fail_count) >= FAIL_LIMIT:
        ttl = r.ttl(fail_key)
        return JSONResponse({
            "result": "REJECT",
            "reason": f"Rate limited — {ttl}s kaldı",
            "rate_limit": {"count": int(fail_count), "limit": FAIL_LIMIT, "ttl": ttl},
        })

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # MAB akışı
        if test_type == "mab" and fake_mac:
            mac_normalized = fake_mac.upper().replace("-", ":").replace(".", ":")
            cur.execute(
                "SELECT username, role, is_active FROM users WHERE UPPER(mac_address) = %s",
                (mac_normalized,),
            )
            row = cur.fetchone()

            if row and row["is_active"]:
                return JSONResponse({
                    "result": "ACCEPT",
                    "reason": f"MAB başarılı — {row['username']} ({row['role']})",
                    "matched_user": row["username"],
                    "role": row["role"],
                })
            return JSONResponse({
                "result": "REJECT",
                "reason": f"Bilinmeyen MAC: {mac_normalized}",
            })

        # PAP akışı
        if fake_password:
            cur.execute(
                "SELECT password, is_active, role FROM users WHERE username = %s",
                (fake_username,),
            )
            user = cur.fetchone()

            if not user:
                _increment_fail(fail_key)
                fc = int(r.get(fail_key) or 0)
                return JSONResponse({
                    "result": "REJECT",
                    "reason": "Kullanıcı bulunamadı",
                    "rate_limit": {"count": fc, "limit": FAIL_LIMIT},
                })

            if not user["is_active"]:
                return JSONResponse({"result": "REJECT", "reason": "Hesap deaktif"})

            try:
                if bcrypt.checkpw(fake_password.encode("utf-8"), user["password"].encode("utf-8")):
                    r.delete(fail_key)
                    return JSONResponse({
                        "result": "ACCEPT",
                        "reason": f"PAP doğrulama başarılı",
                        "role": user["role"],
                    })
            except Exception:
                pass

            _increment_fail(fail_key)
            fc = int(r.get(fail_key) or 0)
            return JSONResponse({
                "result": "REJECT",
                "reason": "Yanlış şifre",
                "rate_limit": {"count": fc, "limit": FAIL_LIMIT},
            })

        return JSONResponse({"result": "REJECT", "reason": "Eksik bilgi"})

    finally:
        cur.close()
        conn.close()


@app.post("/dashboard/accounting-test")
async def dashboard_accounting_test(request: Request):
    """
    Dashboard'dan accounting testi.
    Start / Interim-Update / Stop paketlerini simüle eder ve radacct'a yazar.
    """
    data = await request.json()
    username = data.get("username", "testuser")
    action = data.get("action", "Start")  # Start, Interim-Update, Stop
    session_id = data.get("session_id", f"DASH_{int(time.time())}")

    acct_payload = {
        "username": username,
        "status": action,
        "session_id": session_id,
        "nas_ip": "10.0.0.1",
        "nas_port": "GigabitEthernet0/1",
        "input_octets": data.get("input_octets", 0),
        "output_octets": data.get("output_octets", 0),
        "session_time": data.get("session_time", 0),
    }

    # Internal olarak accounting fonksiyonunu çağır
    acct_unique = f"{username}_{session_id}"
    redis_key = f"session:{session_id}"
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()

    try:
        if action == "Start":
            cur.execute(
                """INSERT INTO radacct
                   (acctsessionid, acctuniqueid, username, nasipaddress,
                    nasportid, acctstarttime, acctupdatetime,
                    acctinputoctets, acctoutputoctets, callingstationid)
                   VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), 0, 0, '')
                   ON CONFLICT DO NOTHING""",
                (session_id, acct_unique, username, "10.0.0.1", "Gi0/1"),
            )
            conn.commit()
            r.set(redis_key, json.dumps({
                "username": username,
                "session_id": session_id,
                "nas_ip": "10.0.0.1",
                "start_time": now,
                "input_octets": 0,
                "output_octets": 0,
                "session_time": 0,
            }))
            return {"status": "ok", "message": f"Accounting-Start: {session_id}", "session_id": session_id}

        elif action == "Interim-Update":
            inp = int(data.get("input_octets", 5000))
            outp = int(data.get("output_octets", 3000))
            sess_time = int(data.get("session_time", 120))
            cur.execute(
                """UPDATE radacct SET acctupdatetime=NOW(), acctsessiontime=%s,
                   acctinputoctets=%s, acctoutputoctets=%s
                   WHERE acctsessionid=%s AND username=%s""",
                (sess_time, inp, outp, session_id, username),
            )
            conn.commit()
            existing = r.get(redis_key)
            if existing:
                sess = json.loads(existing)
                sess.update({"input_octets": inp, "output_octets": outp, "session_time": sess_time})
                r.set(redis_key, json.dumps(sess))
            return {"status": "ok", "message": f"Interim-Update: {inp}B in / {outp}B out"}

        elif action == "Stop":
            inp = int(data.get("input_octets", 10000))
            outp = int(data.get("output_octets", 8000))
            sess_time = int(data.get("session_time", 300))
            cur.execute(
                """UPDATE radacct SET acctstoptime=NOW(), acctupdatetime=NOW(),
                   acctsessiontime=%s, acctinputoctets=%s, acctoutputoctets=%s,
                   acctterminatecause='User-Request'
                   WHERE acctsessionid=%s AND username=%s""",
                (sess_time, inp, outp, session_id, username),
            )
            conn.commit()
            r.delete(redis_key)
            return {"status": "ok", "message": f"Accounting-Stop: oturum sonlandırıldı"}

    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        cur.close()
        conn.close()