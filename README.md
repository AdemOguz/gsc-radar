# GSC Radar

GSC Radar, Google Search Console (GSC) ve Google Analytics 4 (GA4) verilerini tek panelde toplayan, SEO ekipleri ve ajanslar icin tasarlanmis bir SaaS SEO operasyon platformudur.

Bu projede amac sadece veri gostermek degil; neden-sonuc analizi, aksiyon onceliklendirmesi ve musteriye sunulabilir raporlama ile karar almayi hizlandirmaktir.

## Icindekiler

1. [Hizmetler](#hizmetler)
2. [Teknoloji Mimarisi](#teknoloji-mimarisi)
3. [Kurulum](#kurulum)
4. [Ortam Degiskenleri](#ortam-degiskenleri)
5. [Calistirma](#calistirma)
6. [Ilk Kurulum Kontrol Listesi](#ilk-kurulum-kontrol-listesi)
7. [API Ozeti](#api-ozeti)
8. [Guvenlik ve Yetki Modeli](#guvenlik-ve-yetki-modeli)
9. [Yaygin Sorunlar](#yaygin-sorunlar)

## Hizmetler

Asagida uygulamadaki hizmetler urun diliyle tek tek anlatilmistir.

### 1) Ana Sayfa (Marketing Landing)
- Konum: `static/home.html`
- Ne ise yarar:
  - GSC Radar urununu pazarlama diliyle anlatir.
  - Ziyaretciyi urun modullerine yonlendirir.
- Kim kullanir:
  - Potansiyel musteriler, demo kullanicilar.
- Cikti:
  - Servis kartlari, cagrilar (CTA), rehber ve rapor orneklerine yonlendirme.

### 2) Uyelik ve Giris Sistemi
- Backend: `auth.py`, `deps.py`
- Ekran: `static/login.html`
- Ne ise yarar:
  - E-posta/sifre ile uye kaydi ve giris.
  - Google OAuth baglantisi (GSC + GA4 readonly izinleri).
- Kim kullanir:
  - Tum son kullanicilar.
- Cikti:
  - Session cookie tabanli guvenli oturum.

### 3) Site Secim ve Aktivasyon
- Ekran: `static/site-select.html`
- API:
  - `POST /sites/from-gsc`
  - `POST /sites`
  - `GET /sites`
- Ne ise yarar:
  - Kullaniciya ait GSC sitelerinden projeye site tanimlama.
  - Yetkili olunan sitelerle calisma.
- Kim kullanir:
  - SEO uzmanlari, proje yoneticileri.
- Cikti:
  - Site kimligi (`site_id`) ve projeye bagli calisma alani.

### 4) Saglik Komuta Merkezi
- Ekran: `static/health-dashboard.html`
- API:
  - `GET /sites/{site_id}/health`
  - `GET /sites/{site_id}/health/timeline`
  - `POST /sites/{site_id}/health/run`
  - `GET /sites/{site_id}/alerts`
  - `GET /sites/{site_id}/alerts/smart`
- Ne ise yarar:
  - SEO saglik skorunu izler.
  - Kritik/uyari sinifinda alarmlar uretir.
  - Trend ve zaman serisi takibi yapar.
- Kim kullanir:
  - Operasyon ekibi, teknik SEO ekibi.
- Cikti:
  - Saglik skoru, alarm listesi, oncelikli mudahale alanlari.

### 5) Keyword Intelligence
- Ekran: `static/keywords-dashboard.html`
- API:
  - `POST /sites/{site_id}/keywords/fetch`
  - `GET /sites/{site_id}/keywords`
  - `GET /sites/{site_id}/keywords/analytics`
  - `GET /sites/{site_id}/keywords/intent-clusters`
  - `GET /sites/{site_id}/keywords/{keyword}/history`
- Ne ise yarar:
  - Anahtar kelime pozisyon takibi ve analiz.
  - Niyet (intent) kumelenmesi.
  - Keyword gecmisi, CTR/click/impression kirilimlari.
  - Disa aktarma (PDF/XLSX) odakli kullanim akisi.
- Kim kullanir:
  - SEO uzmanlari, icerik ekipleri.
- Cikti:
  - Hedef keyword listeleri, trendler, firsat alanlari.

### 6) Growth Tools (Gelisimis Araclar)
- Ekran: `static/advanced-dashboard.html`
- Ne ise yarar:
  - Taktiksel optimizasyon araclarini tek panelde sunar.

Alt araclar:
- What Changed?
  - API: `GET /sites/{site_id}/growth/what-changed`
  - Son donemde dususun veya yukselisin nedenlerini aciklar.
- Anomaly Cause Score
  - API: `GET /sites/{site_id}/growth/anomaly-cause-score`
  - Anomaliye etki eden nedenleri skorlar.
- Recovery Plan
  - API: `GET /sites/{site_id}/growth/recovery-plan`
  - Dususler icin onceliklendirilmis toparlanma plani verir.
- SERP Snippet CTR Score
  - API: `POST /sites/{site_id}/growth/serp-snippet-score`
  - Title/meta degisikliklerinin CTR etkisini on gorur.
- Sayfa Bazli Firsatlar
  - API: `GET /sites/{site_id}/content/opportunities`
  - Sayfa performansina gore icerik firsatlarini listeler.
- Icerik Revizyon Onerisi
  - API: `GET /sites/{site_id}/content/revision-suggestions`
  - Sayfaya ozel duzeltme/revizyon tavsiyesi sunar.
- Cannibalization
  - API: `GET /sites/{site_id}/keywords/cannibalization`
  - Birden fazla URL'in ayni sorguda yarismasini tespit eder.
- Internal Link Onerileri
  - API: `GET /sites/{site_id}/internal-link/suggestions`
  - URL'ler arasi ic link firsatlari onerir.
- Teknik Crawl
  - API: `POST /sites/{site_id}/technical/crawl`
  - Teknik SEO kontrolu icin URL tarama sonucu uretir.
- CTR Testleri
  - API:
    - `POST /sites/{site_id}/ctr-tests`
    - `GET /sites/{site_id}/ctr-tests`
    - `POST /sites/{site_id}/ctr-tests/{test_id}/snapshot`
  - Deney olusturur, sonuc snapshot'i alir.
- Backlink Watchlist
  - API:
    - `POST /sites/{site_id}/backlinks/watchlist`
    - `POST /sites/{site_id}/backlinks/watchlist/check`
    - `POST /sites/{site_id}/backlinks/snapshot`
    - `GET /sites/{site_id}/backlinks/overview`
  - Yeni/kayip/toxic backlink degisimlerini izler, webhook ile bildirir.
- KPI Hedef Takibi
  - API:
    - `POST /sites/{site_id}/kpi/goals`
    - `GET /sites/{site_id}/kpi/dashboard`
  - Hedef bazli ilerleme ve risk gorunumu.

### 7) Aylik SEO Raporu (White-label)
- Ekran: `static/monthly-seo-report.html`
- API:
  - `GET /sites/{site_id}/seo/monthly-report`
  - `POST /sites/{site_id}/seo/competitor-analysis`
  - `GET /sites/{site_id}/reports/notes`
  - `POST /sites/{site_id}/reports/notes`
  - `POST /sites/{site_id}/pdf/templates`
  - `GET /sites/{site_id}/pdf/templates`
  - `GET /sites/{site_id}/pdf/report`
- Ne ise yarar:
  - Yonetici ozeti + teknik detay + aksiyon plani formatinda rapor uretir.
  - Marka renk/logo ile white-label sunum hazirlar.
  - Musteri notlari ve paylasim linkiyle teslim surecini guclendirir.
- Kim kullanir:
  - Ajans sahipleri, hesap yoneticileri.
- Cikti:
  - Estetik ve paylasilabilir aylik rapor (PDF odakli).

### 8) Admin Panel
- Ekran: `static/admin-users.html`
- API:
  - `GET /admin/users`
  - `GET /admin/users/{member_user_id}/activities`
- Ne ise yarar:
  - Kayitli uyeleri listeler.
  - Uyenin yaptigi islemleri (log) acilir panel ile gosterir.
- Kim kullanir:
  - Sadece admin e-posta listesinde olan kullanicilar.
- Cikti:
  - Operasyonel denetim ve kullanici aktivite gorunurlugu.

### 9) Rehber Sayfasi
- Ekran: `static/guide.html`
- Ne ise yarar:
  - Tum ozellikleri kullanim senaryolariyla anlatir.
  - Yeni kullanicinin platformu hizli ogrenmesini saglar.
- Kim kullanir:
  - Ilk kez kullanan ekipler, onboarding sureci.

## Teknoloji Mimarisi

- Backend: FastAPI
- ORM: SQLAlchemy
- Veritabani: PostgreSQL (zorunlu)
- Frontend: Vanilla HTML/CSS/JS (moduler static sayfalar)
- Entegrasyonlar:
  - Google Search Console API
  - Google Analytics Data API
  - Google Analytics Admin API

Onemli not:
- `database.py` yalnizca PostgreSQL baglantisini kabul eder.
- `sqlite` desteklenmez.

## Kurulum

### 1) Python ortami
```bash
python -m venv .venv
.venv\\Scripts\\activate
```

### 2) Paket kurulumu
```bash
pip install fastapi uvicorn sqlalchemy psycopg2-binary requests google-api-python-client google-auth google-auth-oauthlib pydantic[email]
```

### 3) PostgreSQL
Asagidaki bilgilerle bir PostgreSQL sunucusu calisir durumda olmali:
- Image: `postgres:15`
- Host: `localhost`
- Port: `5432`
- DB: `appdb`
- User: `postgres`
- Password: `postgres123`

## Ortam Degiskenleri

Minimum `.env` ornegi:

```env
DATABASE_URL=postgresql://postgres:postgres123@localhost:5432/appdb

POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123
POSTGRES_DB=appdb
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Opsiyonel
ADMIN_EMAILS=ademoguz12@gmail.com
SESSION_COOKIE_SECURE=0
ENABLE_DAILY_HEALTH_WORKER=0
APP_PASSWORD_HASH_ITERATIONS=210000
LOGIN_RATE_LIMIT_WINDOW_SEC=900
LOGIN_RATE_LIMIT_MAX_ATTEMPTS=6
```

## Calistirma

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Acilis URL'i:
- `http://localhost:8000/`

## Ilk Kurulum Kontrol Listesi

1. Uygulamayi acip hesap olusturun (`/static/login.html`).
2. Google hesabini baglayin (GSC + GA4 readonly).
3. Site secimi yapin (`/static/site-select.html`).
4. Health panelinde ilk veri cekimini calistirin.
5. Keyword verilerini fetch edin.
6. Growth Tools ekraninda What Changed + Recovery Plan'i test edin.
7. Aylik raporda musteri adi/logo/renk girerek PDF ciktisi alin.
8. Gerekirse admin panelinden uye hareketlerini kontrol edin.

## API Ozeti

Tam endpoint listesi icin `main.py` icindeki route tanimlarina bakabilirsiniz.

Temel gruplar:
- Kimlik ve OAuth: `/auth/*`
- Site ve dashboard: `/sites/*`
- Growth analizleri: `/sites/{site_id}/growth/*`
- Keyword modulu: `/sites/{site_id}/keywords*`
- Icerik/teknik araclar: `/sites/{site_id}/content/*`, `/sites/{site_id}/technical/*`
- Raporlama: `/sites/{site_id}/seo/*`, `/sites/{site_id}/pdf/*`, `/sites/{site_id}/reports/*`
- Admin: `/admin/*`
- Is planlayici: `/jobs/*`

## Guvenlik ve Yetki Modeli

- Session cookie tabanli oturum yonetimi.
- Login zorunlulugu middleware ile korunur.
- Origin/Referer kontrolu ile temel CSRF azaltimi uygulanir.
- Guvenlik basliklari aktif:
  - `Content-Security-Policy`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy`
- Admin erisimi `ADMIN_EMAILS` ile sinirlanir.
- Kullanici aktiviteleri `user_activity_logs` tablosuna kaydedilir.

## Yaygin Sorunlar

### 1) GA4 property yetki hatasi (403)
- Mesaj: `User does not have sufficient permissions for this property`
- Cozum:
  - Dogru `ga4_property_id` kullandiginizi kontrol edin.
  - Google Analytics tarafinda en az Viewer yetkisi verin.

### 2) Admin API disabled
- Mesaj: `analyticsadmin.googleapis.com ... disabled`
- Cozum:
  - Google Cloud Console'dan Analytics Admin API'yi aktif edin.

### 3) Backlink watchlist bos sonuc
- Neden:
  - Snapshot verisi yoksa karsilastirma yapilamaz.
- Cozum:
  - Once `/backlinks/snapshot` ile veri kaydedin, sonra check calistirin.

### 4) PostgreSQL baglanti hatasi
- Cozum:
  - `DATABASE_URL` dogru mu kontrol edin.
  - Veritabani servisinin ayakta oldugunu dogrulayin.

---

## Lisans

Bu depo icin lisans bilgisi henuz tanimlanmamistir. GitHub'a yuklemeden once uygun bir lisans dosyasi (`LICENSE`) eklemeniz onerilir.
