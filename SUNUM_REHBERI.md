# 🎬 Video Sunumu: Kodları Anlatma Rehberi

Videoda kodları anlatırken **tüm dosyayı satır satır anlatmana GEREK YOKTUR**. Bu hem sıkıcı olur hem de süreyi uzatır. Sadece değerlendiricilerin (mühendislerin) aradığı **kilit noktaları** (Authentication, Authorization, Accounting, Güvenlik) göstermen yeterlidir. 

Videoyu çekerken VS Code'da ilgili dosyayı ve satırı açıp şu sırayla anlatabilirsin:

---

## 1. FreeRADIUS PAP ve MAB'ı Nasıl Ayırt Ediyor?
**📂 Dosya:** `radius/default_actual`
**🔍 Gösterilecek Yer:** `authorize` bloğu (300. satırlar civarı)

**🗣️ Ne Söyleyeceksin:**
> *"FreeRADIUS'a bir istek geldiğinde önce authorize bloğuna girer. Burada basit bir mantık kurdum: Eğer gelen pakette `User-Password` varsa, bu bir PAP/CHAP isteğidir ve kimlik doğrulama için REST API'ye yönlendirilir (Auth-Type := rest). Eğer şifre yoksa ama `Calling-Station-Id` (MAC adresi) varsa, bu bir MAB isteğidir. Bu durumda MAC adresini User-Name olarak atayıp yine doğrulama için REST API'ye gönderiyorum. Böylece her iki senaryo da tek bir merkezi API'de çözülüyor."*

---

## 2. API Bağlantısı (rlm_rest)
**📂 Dosya:** `radius/queries.conf`
**🔍 Gösterilecek Yer:** `authenticate` ve `authorize` endpoint tanımları

**🗣️ Ne Söyleyeceksin:**
> *"FreeRADIUS standart SQL modülü yerine `rlm_rest` modülünü kullanıyor. Burada `queries.conf` dosyasında FreeRADIUS'un parametrelerini JSON formatına çevirip FastAPI'deki `/auth` ve `/authorize` endpointlerine nasıl gönderdiğini görebilirsiniz. Bu yapı sayesinde iş kurallarını (policy) esnek bir şekilde Python tarafında yönetebiliyorum."*

---

## 3. Güvenlik: Şifreler Nasıl Saklanıyor?
**📂 Dosya:** `schema.sql`
**🔍 Gösterilecek Yer:** `users` tablosu `password` alanı ve Seed Data (`gen_salt` kısmı)

**🗣️ Ne Söyleyeceksin:**
> *"Güvenlik gereği veritabanında kesinlikle plaintext (açık metin) şifre saklamıyorum. `schema.sql` içinde pgcrypto eklentisini aktif ettim. Kullanıcılar oluşturulurken şifreler bcrypt algoritması ile hash'lenerek (`gen_salt('bf')`) veritabanına kaydediliyor."*

---

## 4. FastAPI: Kimlik Doğrulama ve Brute-Force Koruması (Rate Limiting)
**📂 Dosya:** `api/main.py`
**🔍 Gösterilecek Yer:** `_pap_auth()` fonksiyonu ve Rate-limit bloğu (100-115 ve 145-160. satırlar arası)

**🗣️ Ne Söyleyeceksin:**
> *"Python tarafındaki en önemli kısımlardan biri kimlik doğrulama. Gelen şifreyi `bcrypt.checkpw()` ile veritabanındaki hash ile karşılaştırıyorum. Ayrıca burada Redis tabanlı bir rate-limiting (hız sınırı) mekanizması var. Bir kullanıcı 3 kez arka arkaya yanlış şifre girerse, Redis tarafında bu kaydediliyor ve hesabı 30 saniyeliğine bloklanıyor. Bu sayede Brute-Force saldırılarını engelliyorum."*

---

## 5. Dinamik VLAN Ataması (Authorization)
**📂 Dosya:** `api/main.py`
**🔍 Gösterilecek Yer:** `@app.post("/authorize")` fonksiyonu (185-210. satırlar)

**🗣️ Ne Söyleyeceksin:**
> *"Kimlik doğrulama başarılı olursa FreeRADIUS `/authorize` endpointine gelir. Burada PostgreSQL'deki `radusergroup` tablosundan kullanıcının rolünü buluyorum (örneğin admin, employee veya guest). Sonra `radgroupreply` tablosundan bu role ait VLAN ID'sini (örneğin Admin için VLAN 10) alıp FreeRADIUS'a RADIUS atribütleri olarak (Tunnel-Private-Group-Id) geri dönüyorum. Böylece ağ anahtarı (switch) kullanıcıyı doğru VLAN'a atayabiliyor."*

---

## 6. Oturum Takibi (Accounting) ve Redis Hızı
**📂 Dosya:** `api/main.py`
**🔍 Gösterilecek Yer:** `@app.post("/accounting")` fonksiyonu (240. satırlar)

**🗣️ Ne Söyleyeceksin:**
> *"Son olarak Accounting kısmı. Kullanıcının oturumu başladığında (Start), devam ederken (Interim) ve bittiğinde (Stop) burası tetiklenir. Burada çift katmanlı bir yapı kurdum: Kalıcı denetim kayıtları için verileri PostgreSQL'e yazıyorum. Ancak anlık 'Aktif Oturumlar'ı hızlıca listeleyebilmek için bu bilgiyi aynı zamanda Redis'te de (session:{id} key'i ile) tutuyorum. Stop paketi geldiğinde Redis'ten siliniyor ama veritabanında geçmiş olarak kalıyor."*

---

### 💡 Video Çekim Taktikleri:
1. VS Code'da dosyalar solda açık DURSUN.
2. Bu 6 adımı anlatırken fare ile bahsettiğin satırları **seç veya vurgula** (Örn: `bcrypt.checkpw` satırının üzerinden fareyle geç).
3. "Ezberlemiş gibi" değil, kendi yazdığın kodu bir iş arkadaşına açıklıyormuş gibi rahat anlat.
4. "Bu satır sayesinde sistem çok hızlı çalışıyor", "Buradaki hash işlemi güvenliği sağlıyor" gibi **fayda odaklı** cümleler mühendisleri her zaman etkiler.
