# Staj Değerlendirme Raporu — NAC (Network Access Control) Sistemi

**Hazırlayan:** Bilal Dariyeri  
**Tarih:** Mart 2026  
**Proje:** RADIUS Tabanlı Ağ Erişim Kontrol Sistemi  
**Teknolojiler:** Docker, FreeRADIUS 3.2, Python 3.13 (FastAPI), PostgreSQL 18, Redis 8

---

## 1. Giriş

Bu projenin amacı, kurumsal ağlarda erişim kontrolü sağlamak üzere RADIUS protokolüne dayalı bir NAC sistemi kurmaktır. Sistem, bir kullanıcının veya cihazın ağa bağlanma talebinden itibaren kimlik doğrulama, yetkilendirme ve oturum takibi işlemlerini uçtan uca yönetir.

Projenin kapsamı AAA mimarisinin üç temel bileşenini kapsar:

| Bileşen | İngilizce | İşlev |
|---------|-----------|-------|
| Kimlik Doğrulama | Authentication | Kullanıcı veya cihaz kim? |
| Yetkilendirme | Authorization | Ne yapabilir, hangi ağ segmentine erişebilir? |
| Hesap Yönetimi | Accounting | Ne kadar süre bağlıydı, ne kadar veri aktardı? |

RADIUS (Remote Authentication Dial-In User Service), RFC 2865 ve RFC 2866 standartlarında tanımlanan bir ağ protokolüdür. İstemci-sunucu modeliyle çalışır: ağ cihazları (switch, access point vb.) istemci rolünde RADIUS sunucusuna sorgular gönderir ve sunucu, merkezileştirilmiş bir veritabanından karar vererek yanıt döner.

Bu projede FreeRADIUS sunucusu, doğrudan veritabanı sorgusu yerine rlm_rest modülü üzerinden bir FastAPI uygulamasına HTTP istekleri yapar. Bu yaklaşım sayesinde kimlik doğrulama ve politika yönetimi programlanabilir bir API katmanına taşınmış olur; böylece iş kuralları değiştiğinde FreeRADIUS yapılandırmasına dokunmaya gerek kalmaz.

---

## 2. Mimari Tasarım

### 2.1 Sistem Bileşenleri

Sistem dört Docker konteynerinden oluşur ve hepsi aynı sanal ağ (nac_net) üzerinde iletişim kurar:

| Servis | Image | Port | Görev |
|--------|-------|------|-------|
| FreeRADIUS | freeradius/freeradius-server:latest-3.2 | 1812/udp, 1813/udp | RADIUS protokolü işleme |
| FastAPI | python:3.13-slim | 8000/tcp | Politika motoru (AAA mantığı) |
| PostgreSQL | postgres:18-alpine | 5432 (internal) | Kullanıcı bilgileri, accounting kayıtları |
| Redis | redis:8-alpine | 6379 (internal) | Rate-limiting sayacı, oturum önbelleği |

### 2.2 Veri Akışı

Bir kullanıcının ağa bağlanma sürecindeki veri akışı şu şekildedir:

1. Kullanıcı veya cihaz, ağ cihazına (NAS) bağlanma isteği gönderir
2. NAS, RADIUS Access-Request paketini FreeRADIUS'a iletir (UDP 1812)
3. FreeRADIUS, authorize aşamasında isteği rlm_rest modülü aracılığıyla FastAPI'ye yönlendirir
4. FastAPI, PostgreSQL'den kullanıcı bilgilerini çeker ve kimlik doğrulamasını yapar
5. Başarılıysa Access-Accept, başarısızsa Access-Reject döner
6. Accept durumunda post-auth aşamasında tekrar API'ye gidilerek VLAN ataması alınır
7. Oturum boyunca accounting paketleri (Start, Interim-Update, Stop) API'ye gönderilir
8. Oturum verileri PostgreSQL'de kalıcı olarak, Redis'te geçici olarak saklanır

### 2.3 Neden rlm_rest?

FreeRADIUS'un sql modülü doğrudan veritabanı sorgusu yapabilir; ancak rlm_rest tercih edilmesinin nedenleri:

- Politika mantığı Python koduyla yönetilir, SQL manipülasyonu gerektirmez
- Bcrypt gibi gelişmiş hash algoritmaları doğrudan kullanılabilir
- Rate-limiting gibi ek güvenlik mekanizmaları kolayca eklenebilir
- API katmanı, farklı RADIUS sunucularından veya servislerden bağımsız olarak test edilebilir
- İleriye dönük genişletilebilirlik: webhook, loglama, LDAP entegrasyonu gibi özellikler API'ye eklenerek FreeRADIUS yapılandırmasına dokunulmadan sistem geliştirilebilir

---

## 3. Uygulama Detayları

### 3.1 Docker Compose Yapılandırması

Tüm servisler tek bir docker-compose.yml dosyasında tanımlanmıştır. Servisler arası bağımlılıklar depends_on ve healthcheck mekanizmalarıyla yönetilir:

| Servis | Healthcheck | Bağımlılık |
|--------|-------------|-----------|
| PostgreSQL | pg_isready komutu | — |
| Redis | redis-cli ping | — |
| FastAPI | HTTP GET /health | PostgreSQL ✓ Redis ✓ |
| FreeRADIUS | radtest komutu | FastAPI ✓ PostgreSQL ✓ Redis ✓ |

Bu yapıda FreeRADIUS en son ayağa kalkar çünkü hem API'nin hem veritabanının hazır olmasını bekler. Environment variable'lar .env dosyasında tutulur ve bu dosya .gitignore ile versiyon kontrolünden çıkarılmıştır. Hassas bilgilerin paylaşılmaması için .env.example dosyası şablon olarak oluşturulmuştur.

### 3.2 Veritabanı Şeması

PostgreSQL'de altı tablo bulunur:

| Tablo | Alan Sayısı | İşlev |
|-------|-------------|-------|
| users | 6 | Kullanıcı bilgileri (bcrypt hash, MAC, rol) |
| radcheck | 4 | FreeRADIUS sql modülü uyumu |
| radreply | 4 | Kullanıcıya dönülecek atribütler |
| radusergroup | 3 | Kullanıcı-grup eşlemeleri |
| radgroupreply | 4 | Grup bazlı VLAN atribütleri |
| radacct | 22 | Accounting kayıtları |

users tablosu bu projede merkezi rol oynar: hem PAP doğrulaması için bcrypt hash'lenmiş şifreler hem de MAB doğrulaması için MAC adresleri bu tabloda tutulur. Şifreler PostgreSQL'in pgcrypto eklentisi ile gen_salt('bf') fonksiyonu kullanılarak bcrypt formatında hashlenir; plaintext şifre hiçbir zaman saklanmaz.

### 3.3 FreeRADIUS Yapılandırması

FreeRADIUS'un üç temel yapılandırma dosyası bulunur:

**clients.conf** — Hangi IP adreslerinin RADIUS sunucusuna istek gönderebileceğini tanımlar. Hem localhost hem de Docker ağı (172.16.0.0/12) tanımlanmıştır. Her istemci için paylaşılan gizli anahtar (shared secret) kullanılır.

**default (sanal sunucu)** — FreeRADIUS'un istek işleme akışını belirleyen unlang konfigürasyonu. Dört ana bölümden oluşur:

| Bölüm | İşlev | Notlar |
|-------|-------|--------|
| authorize | Gelen isteği sınıflandırma | User-Password varsa PAP, Calling-Station-Id varsa MAB |
| authenticate | Kimlik doğrulama | Auth-Type rest ile FastAPI'ye yönlendirilir |
| post-auth | Yetkilendirme | Access-Accept sonrası VLAN ataması |
| accounting | Oturum takibi | Start/Interim/Stop paketleri API'ye iletilir |

**queries.conf (rlm_rest)** — REST modülünün hangi API endpoint'ine hangi RADIUS atribütlerini göndereceğini tanımlar. Üç bölüm içerir: authenticate (/auth), authorize (/authorize) ve accounting (/accounting).

### 3.4 FastAPI Policy Engine

FastAPI uygulaması tüm AAA mantığını barındırır:

**POST /auth — Kimlik Doğrulama**

İki farklı doğrulama yöntemi desteklenir:

- PAP/CHAP: Kullanıcı adı ve şifre ile giriş. Şifre bcrypt ile doğrulanır. Başarısız giriş denemeleri Redis'te fail:{username} anahtarıyla sayılır; 3 başarısız denemede 30 saniye blok uygulanır.
- MAB: Şifre gönderilmeden, sadece MAC adresiyle doğrulama. PostgreSQL'deki users tablosunda mac_address alanı sorgulanır. Kayıtlı ve aktif ise Accept, bilinmeyen MAC adresleri için varsayılan politika Reject'tir.

**POST /authorize — Yetkilendirme**

Başarılı doğrulamadan sonra çağrılır. radusergroup tablosundan kullanıcının grubunu, radgroupreply tablosundan o grubun VLAN atribütlerini çeker:

| Grup | VLAN ID | Açıklama |
|------|---------|----------|
| admin | 10 | Tam erişim |
| employee | 20 | Sınırlı erişim |
| guest | 30 | Yalnızca internet |

VLAN ataması üç RADIUS atribütüyle yapılır: Tunnel-Type (VLAN), Tunnel-Medium-Type (IEEE-802) ve Tunnel-Private-Group-Id (VLAN numarası).

**POST /accounting — Oturum Takibi**

Üç paket türünü işler:

| Paket | PostgreSQL | Redis |
|-------|-----------|-------|
| Start | INSERT radacct | SET session:{id} |
| Interim-Update | UPDATE (octets, süre) | Refresh cache |
| Stop | UPDATE (stop_time) | DELETE key |

Her oturum kaydında kullanıcı adı, NAS IP adresi, oturum süresi, giriş/çıkış veri miktarı (octets) ve başlangıç/bitiş zamanları saklanır.

**GET /users ve GET /sessions/active**

/users endpoint'i PostgreSQL'den kullanıcıları ve grup bilgilerini dönerken, /sessions/active Redis'teki session:* anahtarlarını tarayarak aktif oturumları döner. Bu ayrım kasıtlıdır: aktif oturumlar sık sorgulandığından Redis'in bellek içi hızından yararlanılır.

---

## 4. Güvenlik Değerlendirmesi

### 4.1 Alınan Önlemler

| Önlem | Uygulama Detayı |
|-------|-----------------|
| Şifre güvenliği | bcrypt ile hash, plaintext asla saklanmaz |
| Brute-force koruması | Redis rate-limiting: 3 hata → 30s blok |
| Ağ izolasyonu | Docker bridge network, servisler dışarıdan erişilemez |
| Secret yönetimi | .env dosyası, .gitignore ile repoya dahil edilmez |
| MAB varsayılan politika | Bilinmeyen MAC → Reject (ağa erişim yok) |
| Healthcheck | Her servis kendi sağlık kontrolüne sahip |

### 4.2 Potansiyel Riskler ve İyileştirme Önerileri

| Risk | Mevcut Durum | Öneri |
|------|-------------|-------|
| RADIUS şifresiz iletişim | Shared secret ile korunur | RadSec (RADIUS over TLS) kullanılabilir |
| API kimlik doğrulama yok | Servisler arası güvenli ağda çalışır | API key veya mTLS eklenebilir |
| Redis şifresiz | Docker ağında izole | Redis AUTH etkinleştirilebilir |
| SQL injection | Parametreli sorgular kullanılır | ORM (SQLAlchemy) kullanılabilir |
| Logging | FreeRADIUS debug log mevcut | ELK Stack ile merkezi loglama eklenebilir |

---

## 5. Gerçek Dünya Uygulamaları

### 5.1 Kurumsal Ağ Güvenliği

Büyük ölçekli şirketlerde farklı departmanların farklı ağ erişim seviyelerine ihtiyacı vardır. NAC sistemi ile çalışanlar, misafirler ve IoT cihazları farklı VLAN segmentlerine ayrılır. Bu projede uygulanan admin/employee/guest gruplandırması tam olarak bu senaryoyu modellemektedir. Örneğin bir çalışan Wi-Fi'ya bağlandığında otomatik olarak VLAN 20'ye düşer ve sadece iş ağına erişebilir. Bir misafir ise VLAN 30'a atanır ve yalnızca internet erişimine sahip olur.

Bu yaklaşım sıfır güven (zero trust) mimarisinin temel taşlarından biridir: her cihaz ve kullanıcı kimliğini kanıtlayana kadar güvenilmez kabul edilir.

### 5.2 Sağlık Sektörü ve KVKK Uyumluluğu

Hastanelerde tıbbi cihazlar (MR, röntgen, hasta monitörleri vb.) genellikle ağa bağlıdır ancak 802.1X desteklemez. Bu cihazlar için projede uygulanan MAB özelliği kullanılır: cihazın MAC adresi önceden kaydedilir ve ağa bağlandığında otomatik olarak yetkilendirilir. Sağlık verileri KVKK kapsamında korunması gereken kişisel verilerdir; NAC sistemi ile ağ segmentasyonu yapılarak tıbbi cihazların olduğu ağa yetkisiz cihazların erişmesi engellenir.

### 5.3 ISP ve Telekom Sektörü

İnternet servis sağlayıcıları, abonelerinin kimlik doğrulaması ve kullanım takibi için RADIUS protokolünü yaygın olarak kullanır. Bir abone modemini açtığında PPPoE üzerinden RADIUS sunucusuna kimlik bilgileri gönderilir, doğrulama yapılır ve IP adresi atanır. Projede uygulanan accounting mekanizması, ISP senaryosundaki kullanım takibinin minyatür bir modelidir: oturum süresi ve aktarılan veri miktarı tutularak faturalandırma veya kota yönetimi yapılabilir.

---

## 6. Sonuç ve Öğrenilenler

Bu projeyi geliştirirken edindiğim tecrübeleri şu şekilde özetleyebilirim:

AAA mimarisini teoride bilmekle pratikte uygulamak arasında ciddi fark olduğunu gördüm. FreeRADIUS'un unlang dilini, modül yapısını ve sanal sunucu kavramını anlamak başlangıçta zorlayıcıydı; ancak rlm_rest modülü sayesinde karmaşık RADIUS politikalarını Python'da yazmak mümkün oldu. Bu, geleneksel FreeRADIUS yapılandırmasına kıyasla çok daha esnek ve bakımı kolay bir yaklaşım.

Docker Compose ile çoklu servis yönetimi konusunda healthcheck ve depends_on mekanizmalarının önemini kavradım. Servislerin doğru sırada ayağa kalkması, özellikle veritabanı bağımlılığı olan uygulamalar için hayati öneme sahip.

Redis'in hem rate-limiting hem oturum caching için kullanılması, "doğru araç doğru iş için" prensibini somutlaştırdı: sık sorgulanan veriler (aktif oturumlar) için Redis'in bellek içi hızı, kalıcı kayıtlar (accounting) için PostgreSQL'in ACID garantileri tercih edildi.

Güvenlik açısından bcrypt kullanımı, plaintext şifre risk konusunda farkındalık kazanmamı sağladı. Rate-limiting mekanizması ise basit ama etkili bir brute-force koruması sunuyor; gerçek dünyada bu mekanizma IP bazlı limitler ve CAPTCHA ile güçlendirilebilir.

---

## 7. Kaynaklar

1. RFC 2865 — Remote Authentication Dial In User Service (RADIUS), C. Rigney et al., Haziran 2000
2. RFC 2866 — RADIUS Accounting, C. Rigney, Haziran 2000
3. FreeRADIUS Resmi Dokümantasyonu — https://freeradius.org/documentation/
4. FreeRADIUS rlm_rest Modülü — https://wiki.freeradius.org/modules/rlm_rest
5. FastAPI Resmi Dokümantasyonu — https://fastapi.tiangolo.com/
6. Docker Compose Referansı — https://docs.docker.com/compose/
7. PostgreSQL pgcrypto Eklentisi — https://www.postgresql.org/docs/current/pgcrypto.html
8. Redis Komut Referansı — https://redis.io/commands
9. bcrypt Algoritması — https://en.wikipedia.org/wiki/Bcrypt
10. IEEE 802.1X Standardı — Port-Based Network Access Control
