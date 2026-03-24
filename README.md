# S3M NAC System — Network Access Control

RADIUS protokolü (RFC 2865/2866) tabanlı **AAA** (Authentication, Authorization, Accounting) sistemi.  
FreeRADIUS `rlm_rest` modülü üzerinden FastAPI policy engine ile yönetilir.

## Mimari

```
┌─────────────┐     RADIUS (UDP)     ┌──────────────┐    HTTP/JSON    ┌──────────────┐
│  radtest /  │ ──────────────────▸  │  FreeRADIUS  │ ─────────────▸ │   FastAPI    │
│  radclient  │                      │  :1812 auth  │   (rlm_rest)   │   :8000      │
│             │                      │  :1813 acct  │                │              │
└─────────────┘                      └──────────────┘                └──────┬───────┘
                                                                           │
                                                          ┌────────────────┼────────────────┐
                                                          ▼                                 ▼
                                                   ┌──────────────┐                  ┌──────────────┐
                                                   │  PostgreSQL  │                  │    Redis     │
                                                   │  users       │                  │  rate-limit  │
                                                   │  radacct     │                  │  session     │
                                                   │  radgroup*   │                  │  cache       │
                                                   └──────────────┘                  └──────────────┘
```

## Teknolojiler

| Servis | Image | Rol |
|--------|-------|-----|
| FreeRADIUS | `freeradius/freeradius-server:latest-3.2` | RADIUS sunucusu (auth + acct) |
| PostgreSQL | `postgres:18-alpine` | Kullanıcı, grup, accounting veritabanı |
| Redis | `redis:8-alpine` | Rate-limiting sayacı + oturum cache |
| FastAPI | `python:3.13-slim` | RESTful policy engine |

## Kurulum ve Çalıştırma

```bash
# 1. Repo'yu klonla
git clone <repo-url> && cd S3project

# 2. Environment variables
cp .env.example .env
# .env dosyasını düzenle (şifre, secret vb.)

# 3. Docker Compose ile başlat
docker compose up -d

# 4. Servislerin sağlığını kontrol et
docker compose ps
# Tüm servisler "healthy" olmalı (1-2 dakika bekle)

# ⚠️ Schema değişikliği yaptıysan:
docker compose down -v && docker compose up -d
```

## Demo Kullanıcılar

| Username | Şifre | MAC Adresi | Grup | VLAN |
|----------|-------|-----------|------|------|
| testuser | testing123 | AA:BB:CC:DD:EE:FF | admin | 10 |
| employee1 | employee123 | 11:22:33:44:55:66 | employee | 20 |
| guest1 | guest123 | 22:33:44:55:66:77 | guest | 30 |

## Test Komutları

### 1. PAP Authentication (radtest)

```bash
# ✅ Başarılı giriş
docker exec nac_freeradius radtest testuser testing123 127.0.0.1 0 testing123
# Beklenen: Access-Accept + Tunnel-Private-Group-Id = 10

# ❌ Başarısız giriş
docker exec nac_freeradius radtest testuser yanlis 127.0.0.1 0 testing123
# Beklenen: Access-Reject

# 🔒 Rate Limiting (3 hata → blok)
docker exec nac_freeradius radtest testuser hata1 127.0.0.1 0 testing123
docker exec nac_freeradius radtest testuser hata2 127.0.0.1 0 testing123
docker exec nac_freeradius radtest testuser hata3 127.0.0.1 0 testing123
docker exec nac_freeradius radtest testuser hata4 127.0.0.1 0 testing123
# Beklenen: 4. deneme "Rate limited" ile reddedilir
```

### 2. MAB Test (radclient)

```bash
# ✅ Bilinen MAC
echo "User-Name=AA:BB:CC:DD:EE:FF,Calling-Station-Id=AA:BB:CC:DD:EE:FF" | \
  docker exec -i nac_freeradius radclient 127.0.0.1 auth testing123
# Beklenen: Access-Accept

# ❌ Bilinmeyen MAC
echo "User-Name=FF:FF:FF:FF:FF:FF,Calling-Station-Id=FF:FF:FF:FF:FF:FF" | \
  docker exec -i nac_freeradius radclient 127.0.0.1 auth testing123
# Beklenen: Access-Reject (varsayılan politika: reject)
```

### 3. Accounting (radclient)

```bash
# Start
echo "User-Name=testuser,Acct-Session-Id=sess001,Acct-Status-Type=Start,NAS-IP-Address=192.168.1.1" | \
  docker exec -i nac_freeradius radclient 127.0.0.1 acct testing123

# Interim-Update
echo "User-Name=testuser,Acct-Session-Id=sess001,Acct-Status-Type=Interim-Update,Acct-Session-Time=120,Acct-Input-Octets=5000,Acct-Output-Octets=3000,NAS-IP-Address=192.168.1.1" | \
  docker exec -i nac_freeradius radclient 127.0.0.1 acct testing123

# Stop
echo "User-Name=testuser,Acct-Session-Id=sess001,Acct-Status-Type=Stop,Acct-Session-Time=300,Acct-Input-Octets=10000,Acct-Output-Octets=8000,NAS-IP-Address=192.168.1.1" | \
  docker exec -i nac_freeradius radclient 127.0.0.1 acct testing123
```

### 4. FastAPI Endpoint Testleri (curl)

```bash
# POST /auth — PAP
curl -s -X POST http://localhost:8000/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testing123"}'

# POST /auth — MAB
curl -s -X POST http://localhost:8000/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"AA:BB:CC:DD:EE:FF","mac_address":"AA:BB:CC:DD:EE:FF"}'

# POST /authorize
curl -s -X POST http://localhost:8000/authorize \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser"}'

# POST /accounting
curl -s -X POST http://localhost:8000/accounting \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","status":"Start","session_id":"curl001","nas_ip":"10.0.0.1"}'

# GET /users
curl -s http://localhost:8000/users | python -m json.tool

# GET /sessions/active
curl -s http://localhost:8000/sessions/active | python -m json.tool
```

### 5. Dashboard

Tarayıcıda aç: [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

## API Endpoint'leri

| Endpoint | Metot | İşlev |
|----------|-------|-------|
| `/auth` | POST | Kullanıcı doğrulama (PAP + MAB) |
| `/authorize` | POST | VLAN atribütleri dönme |
| `/accounting` | POST | Oturum verisi kaydetme |
| `/users` | GET | Kullanıcı listesi ve durum |
| `/sessions/active` | GET | Aktif oturumlar (Redis) |
| `/health` | GET | Sağlık kontrolü |
| `/dashboard` | GET | Monitoring arayüzü |

## Proje Yapısı

```
S3project/
├── docker-compose.yml          # Orkestrasyon
├── .env / .env.example         # Environment variables
├── schema.sql                  # PostgreSQL şema + seed data
├── api/
│   ├── main.py                 # FastAPI policy engine
│   ├── requirements.txt        # Python bağımlılıkları
│   └── templates/
│       └── dashboard.html      # Monitoring dashboard
└── radius/
    ├── clients.conf            # RADIUS istemci tanımları
    ├── default_actual          # FreeRADIUS sanal sunucu (unlang)
    └── queries.conf            # rlm_rest modül yapılandırması
```

## Veritabanı Şeması

| Tablo | İçerik |
|-------|--------|
| `users` | Kullanıcılar (bcrypt hash, MAC, rol) |
| `radcheck` | FreeRADIUS auth bilgileri |
| `radreply` | Kullanıcı bazlı dönülecek atribütler |
| `radusergroup` | Kullanıcı ↔ Grup eşlemesi |
| `radgroupreply` | Grup bazlı VLAN atribütleri |
| `radacct` | Accounting kayıtları |
