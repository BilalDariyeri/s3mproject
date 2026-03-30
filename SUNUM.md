---
marp: true
theme: default
paginate: true
backgroundColor: #f8f9fa
---

<!-- _class: lead -->
# Network Access Control (NAC)
### RADIUS Tabanlı Ağ Erişim Kontrol Sistemi

**Hazırlayan:** Bilal Dariyeri
**Kurum:** S3M Security
**Tarih:** Mart 2026

---

## 🔍 Projenin Amacı

Kurumsal ağlarda erişim kontrolü sağlamak için uçtan uca, Dockerize edilmiş bir **AAA (Authentication, Authorization, Accounting)** sistemi kurmak.

- **Authentication:** Kullanıcı kim? (PAP/CHAP veya MAB)
- **Authorization:** Hangi VLAN'a erişebilir?
- **Accounting:** Ne kadar veri aktardı, ne kadar kaldı?

---

## 🏗️ Kullanılan Teknolojiler

- **FreeRADIUS 3.2**: Çekirdek protokol işleyici ve yönlendirici.
- **Python 3.13 (FastAPI)**: REST API altyapısı ve iş kuralları (Policy Engine).
- **PostgreSQL 18**: Kullanıcı verileri, `radacct` oturum geçmişleri, şifre hashleri.
- **Redis 8**: Aktif oturumların tutulması ve brute-force koruması (Rate Limiting).
- **Docker Compose**: Tüm mimarinin tek `nac_net` ağı üzerinde çalıştırılması.

---

## 📡 Mimari Akış ve `rlm_rest`

1. Kullanıcı veya cihaz (Switch, Wi-Fi Controller) Radius isteği gönderir.
2. FreeRADIUS isteği alır. SQL kullanmak yerine, Python'a devretmek için **`rlm_rest`** modülü devreye girer.
3. FreeRADIUS, FastAPI'ye HTTP `POST` atar.
4. FastAPI, PostgreSQL ve Redis ile kontrolleri yapıp `Accept` veya `Reject` döner.

---

## 🛡️ Güvenlik Önlemleri

- **Bcrypt Hashing**: Veritabanında hiçbir zaman açık metin (plaintext) şifre saklanmaz. Pgcrypto ile `gen_salt('bf')` kullanılır.
- **MAB Doğrulaması**: 802.1x desteklemeyen yazıcılar/IoT cihazları sadece MAC adresleri ile doğrulanır.
- **Bilinmeyen MAC Engeli**: Sistemde kayıtlı olmayan MAC'ler `Reject` cevabı alır veya Misafir VLAN'ına yönlendirilir ("Zero Trust").
- **Redis Hız Sınırı**: 3 defa hatalı şifre giren kullanıcı, 30 saniye boyunca **brute-force** korumasına takılarak bloklanır.

---

## 🎯 Dinamik VLAN Ataması

Kimliği başarıyla doğrulanan kullanıcı `/authorize` aşamasında rolüne göre VLAN numarası alır.

| Kullanıcı Grubu | Atanan VLAN ID | Erişim Sınırı     |
| :-------------- | :------------- | :---------------- |
| Admin           | 10             | Sınırsız İzin     |
| Employee        | 20             | Kurum İçi Erişim  |
| Guest           | 30             | İnternet Erişimi  |

---

## 📊 Oturum Takibi (Accounting)

- `Accounting-Start`, `Interim-Update`, `Stop` paketleri FastAPI tarafından işlenir.
- **Kalıcı İzleme (PostgreSQL):** PostgreSQL üzerindeki `radacct` tablosuna yazılır. Geçmişe dönük izleme için idealdir.
- **Hızlı Erişim (Redis):** Aktif oturumlar `session:*` mantığıyla Redis üzerinde geçici olarak barındırılır. Dashboard aktif oturumları saniyeler içinde anında okur.

---

## 🖥️ İnteraktif Dashboard (Premium)

Python Jinja2 kullanılarak yazılmış tek sayfa (SPA) uygulamasıdır. Test ve görüntüleme özellikleri:
- **PAP ve MAB Testleri:** Kod girmeden butonla doğrulama mekanizmalarını test etme.
- **Rate-Limiting Analizi:** Redis üzerinden bar-chart ile canlı hatalı deneme takibi.
- **Accounting Simülatörü:** Radius Start/Stop paketlerini arayüzde simüle edebilme.
- **Canlı Oturum Çizelgesi:** Redis'teki güncel oturumların Auto-Refresh tabanlı listelenmesi.

---

<!-- _class: lead -->
# Dinlediğiniz İçin Teşekkürler
### Soru & Cevap

*S3M Security - Staj Değerlendirme Sunumu*
