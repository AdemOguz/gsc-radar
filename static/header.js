(function () {
  var LANG_KEY = "gsc_radar_lang";
  var allowedLangs = { tr: true, en: true };

  var dictionary = {
    tr: {
      "nav.home": "Ana Sayfa",
      "nav.guide": "Rehber",
      "nav.services": "Hizmetlerimiz",
      "nav.sites": "Siteler",
      "nav.health": "Saglik",
      "nav.advanced": "Gelismis",
      "nav.keywords": "Anahtar Kelimeler",
      "nav.monthly": "Aylik Rapor",
      "nav.members": "Uyeler",
      "nav.login": "Giris",
      "lang.tr": "Turkce",
      "lang.en": "Ingilizce",
      "home.hero_title": "SEO Buyumenin Komuta Merkezi",
      "home.hero_subtitle": "GSC ve GA4 sinyallerini tek yerde birlestir, kayiplari erken yakala ve buyume firsatlarini aninda aksiyona cevir.",
      "home.site_context_label": "Site ID Baglami:",
      "home.site_context_placeholder": "ornek: d01c8e25-3f06-45c9-9de7-9bb362272e51",
      "common.clear": "Temizle",
      "home.context_note": "Site ID baglamini bir kez sec; tum paneller ayni hedef siteyle acilsin, raporlama ve optimizasyon akisinda hiz kaybetme.",
      "common.open": "Ac",
      "home.card.login_title": "Hizli Baslangic",
      "home.card.login_desc": "Dakikalar icinde hesap ac, Google baglantisini tamamla ve veri toplamayi baslat.",
      "home.card.site_title": "Site Aktivasyonu",
      "home.card.site_desc": "Property secimini yap, sistemi tek tikla analize hazir hale getir.",
      "home.card.health_title": "Saglik Komuta Merkezi",
      "home.card.health_desc": "Skor, trend ve alarm akisini ayni ekranda gor; sorunlari buyumeden durdur.",
      "home.card.advanced_title": "Growth Tools",
      "home.card.advanced_desc": "Firsat skoru, kanal karsilastirma ve gelir etkisi yuksek optimizasyon adimlari.",
      "home.card.keywords_title": "Keyword Intelligence",
      "home.card.keywords_desc": "Pozisyon hareketi, firsat sorgulari ve kayip alanlarini otomatik tespit et.",
      "home.card.monthly_title": "White-label Aylik Rapor",
      "home.card.monthly_desc": "Markali PDF, aksiyon plani ve paylasim linki ile musterine premium raporlama deneyimi sun.",
      "site.hero_title": "Google Search Console Sitelerin",
      "site.hero_subtitle": "Analiz etmek istedigin property sec; secim yapinca site otomatik olusturulur.",
      "site.loading": "Yukleniyor...",
      "site.empty": "Hic site bulunamadi",
      "site.permission": "Yetki",
      "site.fetch_error": "GSC site listesi alinamadi",
      "site.create_error": "Site olusturulamadi",
      "site.missing_id": "API site_id dondurmedi",
      "site.select_error_prefix": "Site secimi sirasinda hata:",
      "common.error_prefix": "Hata:",
      "common.site_not_selected": "Site secilmedi",
      "common.no_site_id_to_copy": "Kopyalanacak site id yok",
      "common.site_id_copied": "Site kimligi kopyalandi",
      "common.copy_failed": "Kopyalama basarisiz",
      "common.no_data": "Veri bulunamadi.",
      "common.site_label": "Site:",
      "common.site_select_option": "Site seciniz",
      "login.hero_title": "Uyelik ve Google Baglantisi",
      "login.hero_subtitle": "Once hesap olustur/giris yap, sonra Google Search Console baglantisini tamamla.",
      "login.side_title": "Hizli Giris<br>Temiz Akis",
      "login.side_desc": "Hesabini olustur, oturumunu ac ve Google Search Console baglantisini tek ekrandan yonet.",
      "login.badge.membership": "Uyelik",
      "login.badge.google": "Google Baglantisi",
      "login.badge.panel": "Panel Erisimi",
      "login.panel_title": "Uyelik Islemleri",
      "login.field_name": "Ad Soyad",
      "login.field_email": "E-posta",
      "login.field_password": "Sifre",
      "login.name_placeholder": "Orn: Ali Yilmaz",
      "login.email_placeholder": "ornek@mail.com",
      "login.password_placeholder": "en az 6 karakter",
      "login.register": "Kayit Ol",
      "login.login": "Giris Yap",
      "login.logout": "Cikis Yap",
      "login.connect_google": "Google Search Console Bagla",
      "login.goto_site_select": "Site Secim Ekranina Git",
      "login.google_note": "Google baglantisi icin once giris yapmis olman gerekir.",
      "login.status_checking": "Oturum kontrol ediliyor...",
      "login.status_none": "Oturum yok",
      "login.status_connected": "Giris yapildi: {{name}} ({{email}}) | Google bagli: {{connected}}",
      "login.connected_yes": "Evet",
      "login.connected_no": "Hayir",
      "login.status_error": "Oturum kontrol hatasi",
      "login.error_register": "Kayit hatasi",
      "login.success_register": "Kayit basarili. Simdi giris yapabilirsiniz.",
      "login.error_login": "Giris hatasi",
      "login.login_required": "Once giris yapin",
      "health.hero_title": "Saglik Komuta Merkezi",
      "health.hero_subtitle": "Site sagligini gun gun takip et, trendleri gor, riskleri hizli yakala.",
      "health.range_label": "Analiz Araligi:",
      "health.range_1": "Bugun (1 Gun)",
      "health.range_7": "Son 7 Gun",
      "health.range_14": "Son 14 Gun",
      "health.range_30": "Son 30 Gun",
      "health.run": "Saglik Hesapla",
      "health.copy": "Kopyala",
      "health.tab_list": "Tarihe Gore",
      "health.tab_chart": "Grafik",
      "health.tab_summary": "Ozet",
      "health.status_waiting": "Durum bekleniyor",
      "health.points": "{{count}} veri noktasi",
      "health.last_update": "Son guncelleme: {{date}}",
      "health.chart_score": "Saglik Skoru",
      "health.run_error": "Saglik hesaplanirken hata olustu",
      "health.load_error": "Saglik verisi yuklenemedi",
      "advanced.hero_title": "Gelismis Saglik Analizi",
      "advanced.hero_subtitle": "Genel gorunum, trend, uyari ve zaman cizelgesi verilerini tek noktadan yonet.",
      "advanced.refresh_data": "Verileri Yenile",
      "advanced.tab_overview": "Genel Bakis",
      "advanced.tab_timeline": "Zaman Cizelgesi",
      "advanced.tab_trend": "Egilim",
      "advanced.tab_alerts": "Uyarilar",
      "advanced.tab_growth": "Buyume Araclari",
      "advanced.tab_chart": "Grafik",
      "advanced.action_error_title": "Islem Hatasi",
      "advanced.new_alerts_detected": "{{count}} yeni uyari tespit edildi.",
      "advanced.enter_page_url": "Sayfa URL girin",
      "advanced.select_test": "Test secin",
      "advanced.select_date_range": "Tarih araligi secin",
      "advanced.invalid_date_range": "Baslangic tarihi bitis tarihinden buyuk olamaz",
      "advanced.enter_target_value": "Hedef deger girin",
      "keywords.hero_title": "Anahtar Kelime Pozisyon Takibi",
      "keywords.hero_subtitle": "Anahtar kelime pozisyonlarini, firsatlari ve gecmis egilimleri tek panelde izle.",
      "keywords.fetch": "Anahtar Kelime Verilerini Cek",
      "keywords.range_label": "Veri Araligi:",
      "keywords.search_placeholder": "Anahtar kelime ara...",
      "keywords.sort_label": "Sirala:",
      "keywords.tab_all": "Tum Anahtar Kelimeler",
      "keywords.tab_analytics": "Analitik",
      "keywords.tab_history": "Anahtar Kelime Gecmisi",
      "keywords.prompt_limit": "Kac keyword cekilsin? (Onerilen: 100-500)",
      "keywords.fetch_result": "Gelen: {{received}} | Kaydedilen: {{saved}}",
      "keywords.fetch_error": "Anahtar kelime verileri cekilemedi",
      "keywords.no_data_yet": "Henuz anahtar kelime verisi yok.",
      "keywords.no_analytics_data": "Veri yok (en az 7 gunluk veri gerekli)",
      "keywords.select_site_and_keyword": "Site ve anahtar kelime seciniz",
      "keywords.history_not_found": "Bu anahtar kelime icin gecmis veri bulunamadi",
      "monthly.hero_title": "Aylik Detayli SEO Raporu",
      "monthly.hero_subtitle": "Musteri seviyesi ozet, teknik bulgular, keyword firsatlari ve aksiyon plani.",
      "monthly.report_month": "Rapor Ay:",
      "monthly.load_report": "Raporu Getir",
      "monthly.download_pdf": "PDF Indir",
      "monthly.data_not_available": "Veri Alinamadi",
      "monthly.report_load_error": "Rapor yuklenirken hata:",
      "monthly.competitor_error": "Rakip analizi hatasi:",
      "monthly.create_report_first": "Once rapor olusturun",
      "monthly.invalid_color": "Renk formati gecersiz. Ornek: #0f4c81 veya rgb(15,76,129)",
      "monthly.generate_share_link": "Paylasim Linki Uret",
      "monthly.share_link_label": "Paylasim Linki:",
      "monthly.copy_share_link": "Linki Kopyala",
      "monthly.share_link_ready": "Paylasim linki hazir",
      "monthly.share_link_missing": "Once paylasim linki olusturun",
      "monthly.share_link_copied": "Paylasim linki kopyalandi",
      "footer.brand_desc": "SEO ekipleri ve ajanslar icin performans komuta merkezi.",
      "footer.col_product": "Urun",
      "footer.col_start": "Hizli Baslangic",
      "footer.link_health": "Saglik Komuta Merkezi",
      "footer.link_growth": "Growth Tools",
      "footer.link_keywords": "Keyword Intelligence",
      "footer.link_report": "White-label Raporlama",
      "footer.link_guide": "Kullanim Rehberi",
      "footer.link_trial": "Ucretsiz Deneme Baslat",
      "footer.link_site": "Site Aktivasyonu",
      "footer.link_report_demo": "Rapor Ornegi",
      "footer.copy_left": "© 2026 GSC Radar. Tum haklari saklidir.",
      "footer.copy_right": "SEO operasyonu icin hiz, netlik ve olculebilir etki."
    },
    en: {
      "nav.home": "Home",
      "nav.guide": "Guide",
      "nav.services": "Services",
      "nav.sites": "Sites",
      "nav.health": "Health",
      "nav.advanced": "Advanced",
      "nav.keywords": "Keywords",
      "nav.monthly": "Monthly Report",
      "nav.members": "Members",
      "nav.login": "Login",
      "lang.tr": "Turkish",
      "lang.en": "English",
      "home.hero_title": "Your SEO Growth Command Center",
      "home.hero_subtitle": "Unify GSC and GA4 signals in one place, catch losses early, and turn growth opportunities into clear action.",
      "home.site_context_label": "Site ID Context:",
      "home.site_context_placeholder": "example: d01c8e25-3f06-45c9-9de7-9bb362272e51",
      "common.clear": "Clear",
      "home.context_note": "Set the site context once; every dashboard opens on the same target so your reporting and optimization flow stays fast.",
      "common.open": "Open",
      "home.card.login_title": "Fast Onboarding",
      "home.card.login_desc": "Create your account, connect Google, and start collecting data in minutes.",
      "home.card.site_title": "Site Activation",
      "home.card.site_desc": "Pick your property and make the workspace analysis-ready with one click.",
      "home.card.health_title": "Health Command Center",
      "home.card.health_desc": "Track score, trend, and alerts together to stop issues before they scale.",
      "home.card.advanced_title": "Growth Tools",
      "home.card.advanced_desc": "Opportunity score, channel comparison, and high-impact optimization actions.",
      "home.card.keywords_title": "Keyword Intelligence",
      "home.card.keywords_desc": "Detect movement, opportunities, and loss areas with actionable query insights.",
      "home.card.monthly_title": "White-label Monthly Report",
      "home.card.monthly_desc": "Deliver premium client reporting with branded PDF, action plan, and a share-ready link.",
      "site.hero_title": "Your Google Search Console Sites",
      "site.hero_subtitle": "Select the property you want to analyze; a site is created automatically after selection.",
      "site.loading": "Loading...",
      "site.empty": "No site found",
      "site.permission": "Permission",
      "site.fetch_error": "Could not fetch GSC site list",
      "site.create_error": "Could not create site",
      "site.missing_id": "API did not return site_id",
      "site.select_error_prefix": "Error while selecting site:",
      "common.error_prefix": "Error:",
      "common.site_not_selected": "Site is not selected",
      "common.no_site_id_to_copy": "No site id to copy",
      "common.site_id_copied": "Site ID copied",
      "common.copy_failed": "Copy failed",
      "common.no_data": "No data found.",
      "common.site_label": "Site:",
      "common.site_select_option": "Select a site",
      "login.hero_title": "Membership and Google Connection",
      "login.hero_subtitle": "First create an account/login, then complete your Google Search Console connection.",
      "login.side_title": "Fast Access<br>Clean Flow",
      "login.side_desc": "Create your account, sign in, and manage Google Search Console connection from a single screen.",
      "login.badge.membership": "Membership",
      "login.badge.google": "Google Connection",
      "login.badge.panel": "Panel Access",
      "login.panel_title": "Membership Actions",
      "login.field_name": "Full Name",
      "login.field_email": "Email",
      "login.field_password": "Password",
      "login.name_placeholder": "Ex: Alex Johnson",
      "login.email_placeholder": "example@mail.com",
      "login.password_placeholder": "at least 6 characters",
      "login.register": "Register",
      "login.login": "Login",
      "login.logout": "Logout",
      "login.connect_google": "Connect Google Search Console",
      "login.goto_site_select": "Go to Site Selection",
      "login.google_note": "You must be logged in before connecting Google.",
      "login.status_checking": "Checking session...",
      "login.status_none": "No active session",
      "login.status_connected": "Logged in: {{name}} ({{email}}) | Google connected: {{connected}}",
      "login.connected_yes": "Yes",
      "login.connected_no": "No",
      "login.status_error": "Session check error",
      "login.error_register": "Registration error",
      "login.success_register": "Registration successful. You can now login.",
      "login.error_login": "Login error",
      "login.login_required": "Please login first",
      "health.hero_title": "Health Command Center",
      "health.hero_subtitle": "Track site health day by day, see trends, and catch risks quickly.",
      "health.range_label": "Analysis Range:",
      "health.range_1": "Today (1 Day)",
      "health.range_7": "Last 7 Days",
      "health.range_14": "Last 14 Days",
      "health.range_30": "Last 30 Days",
      "health.run": "Calculate Health",
      "health.copy": "Copy",
      "health.tab_list": "By Date",
      "health.tab_chart": "Chart",
      "health.tab_summary": "Summary",
      "health.status_waiting": "Waiting for status",
      "health.points": "{{count}} data points",
      "health.last_update": "Last update: {{date}}",
      "health.chart_score": "Health Score",
      "health.run_error": "An error occurred while calculating health",
      "health.load_error": "Health data could not be loaded",
      "advanced.hero_title": "Advanced Health Intelligence",
      "advanced.hero_subtitle": "Manage overview, trend, alert and timeline data from one place.",
      "advanced.refresh_data": "Refresh Data",
      "advanced.tab_overview": "Overview",
      "advanced.tab_timeline": "Timeline",
      "advanced.tab_trend": "Trend",
      "advanced.tab_alerts": "Alerts",
      "advanced.tab_growth": "Growth Tools",
      "advanced.tab_chart": "Chart",
      "advanced.action_error_title": "Action Error",
      "advanced.new_alerts_detected": "{{count}} new alerts detected.",
      "advanced.enter_page_url": "Enter page URL",
      "advanced.select_test": "Select a test",
      "advanced.select_date_range": "Select date range",
      "advanced.invalid_date_range": "Start date cannot be greater than end date",
      "advanced.enter_target_value": "Enter target value",
      "keywords.hero_title": "Keyword Position Tracker",
      "keywords.hero_subtitle": "Track keyword positions, opportunities, and historical trends in one panel.",
      "keywords.fetch": "Fetch Keyword Data",
      "keywords.range_label": "Data Range:",
      "keywords.search_placeholder": "Search keyword...",
      "keywords.sort_label": "Sort:",
      "keywords.tab_all": "All Keywords",
      "keywords.tab_analytics": "Analytics",
      "keywords.tab_history": "Keyword History",
      "keywords.prompt_limit": "How many keywords to fetch? (Recommended: 100-500)",
      "keywords.fetch_result": "Received: {{received}} | Saved: {{saved}}",
      "keywords.fetch_error": "Keyword data could not be fetched",
      "keywords.no_data_yet": "No keyword data yet.",
      "keywords.no_analytics_data": "No data (at least 7 days of data required)",
      "keywords.select_site_and_keyword": "Select site and keyword",
      "keywords.history_not_found": "No historical data found for this keyword",
      "monthly.hero_title": "Monthly Detailed SEO Report",
      "monthly.hero_subtitle": "Client-level summary, technical findings, keyword opportunities, and action plan.",
      "monthly.report_month": "Report Month:",
      "monthly.load_report": "Load Report",
      "monthly.download_pdf": "Download PDF",
      "monthly.data_not_available": "Data Not Available",
      "monthly.report_load_error": "Error while loading report:",
      "monthly.competitor_error": "Competitor analysis error:",
      "monthly.create_report_first": "Create a report first",
      "monthly.invalid_color": "Invalid color format. Example: #0f4c81 or rgb(15,76,129)",
      "monthly.generate_share_link": "Generate Share Link",
      "monthly.share_link_label": "Share Link:",
      "monthly.copy_share_link": "Copy Link",
      "monthly.share_link_ready": "Share link is ready",
      "monthly.share_link_missing": "Generate a share link first",
      "monthly.share_link_copied": "Share link copied",
      "footer.brand_desc": "Performance command center for SEO teams and agencies.",
      "footer.col_product": "Product",
      "footer.col_start": "Get Started",
      "footer.link_health": "Health Command Center",
      "footer.link_growth": "Growth Tools",
      "footer.link_keywords": "Keyword Intelligence",
      "footer.link_report": "White-label Reporting",
      "footer.link_guide": "Usage Guide",
      "footer.link_trial": "Start Free Trial",
      "footer.link_site": "Site Activation",
      "footer.link_report_demo": "Report Sample",
      "footer.copy_left": "© 2026 GSC Radar. All rights reserved.",
      "footer.copy_right": "Speed, clarity, and measurable impact for SEO operations."
    }
  };

  function getSavedLang() {
    var saved = localStorage.getItem(LANG_KEY) || "tr";
    return allowedLangs[saved] ? saved : "tr";
  }

  var currentLang = getSavedLang();

  function format(template, params) {
    if (!params) return template;
    return template.replace(/\{\{(\w+)\}\}/g, function (_, key) {
      return params[key] == null ? "" : String(params[key]);
    });
  }

  function t(key, fallback, params) {
    var langDict = dictionary[currentLang] || {};
    var value = langDict[key];
    if (typeof value === "undefined") value = fallback || key;
    return format(value, params);
  }

  function setLang(lang) {
    if (!allowedLangs[lang]) return;
    currentLang = lang;
    localStorage.setItem(LANG_KEY, lang);
    document.documentElement.setAttribute("lang", lang);
    applyPageTranslations();
    renderHeader();
    renderFooter();
    syncLangButtons();
    window.dispatchEvent(new CustomEvent("gsc:lang-changed", { detail: { lang: lang } }));
  }

  function applyPageTranslations() {
    var textNodes = document.querySelectorAll("[data-i18n]");
    textNodes.forEach(function (el) {
      var key = el.getAttribute("data-i18n");
      if (!key) return;
      el.innerHTML = t(key, el.innerHTML);
    });

    var placeholders = document.querySelectorAll("[data-i18n-placeholder]");
    placeholders.forEach(function (el) {
      var key = el.getAttribute("data-i18n-placeholder");
      if (!key) return;
      el.setAttribute("placeholder", t(key, el.getAttribute("placeholder") || ""));
    });

    var titles = document.querySelectorAll("[data-i18n-title]");
    titles.forEach(function (el) {
      var key = el.getAttribute("data-i18n-title");
      if (!key) return;
      el.setAttribute("title", t(key, el.getAttribute("title") || ""));
    });

    applySelectorTranslations();
  }

  function applySelectorTranslations() {
    var path = window.location.pathname || "";
    var pages = {
      "/static/health-dashboard.html": [
        { selector: ".hero-title", key: "health.hero_title" },
        { selector: ".hero-subtitle", key: "health.hero_subtitle" },
        { selector: "#siteSelect option[value='']", key: "common.site_select_option" },
        { selector: "#range option[value='1']", key: "health.range_1" },
        { selector: "#range option[value='7']", key: "health.range_7" },
        { selector: "#range option[value='14']", key: "health.range_14" },
        { selector: "#range option[value='30']", key: "health.range_30" },
        { selector: ".toolbar button[onclick='runHealth()']", key: "health.run" },
        { selector: ".site-id-box button", key: "health.copy" },
        { selector: ".tab-button:nth-of-type(1)", key: "health.tab_list" },
        { selector: ".tab-button:nth-of-type(2)", key: "health.tab_chart" },
        { selector: ".tab-button:nth-of-type(3)", key: "health.tab_summary" }
      ],
      "/static/advanced-dashboard.html": [
        { selector: ".hero-title", key: "advanced.hero_title" },
        { selector: ".hero-subtitle", key: "advanced.hero_subtitle" },
        { selector: "#siteSelect option[value='']", key: "common.site_select_option" },
        { selector: ".toolbar button.btn-secondary[onclick='loadAllData()']", key: "advanced.refresh_data" },
        { selector: ".tab-button:nth-of-type(1)", key: "advanced.tab_overview" },
        { selector: ".tab-button:nth-of-type(2)", key: "advanced.tab_timeline" },
        { selector: ".tab-button:nth-of-type(3)", key: "advanced.tab_trend" },
        { selector: ".tab-button:nth-of-type(4)", key: "advanced.tab_alerts" },
        { selector: ".tab-button:nth-of-type(5)", key: "advanced.tab_growth" },
        { selector: ".tab-button:nth-of-type(6)", key: "advanced.tab_chart" }
      ],
      "/static/keywords-dashboard.html": [
        { selector: ".hero-title", key: "keywords.hero_title" },
        { selector: ".hero-subtitle", key: "keywords.hero_subtitle" },
        { selector: "#siteSelect option[value='']", key: "common.site_select_option" },
        { selector: ".toolbar button.btn-success[onclick='fetchKeywords()']", key: "keywords.fetch" },
        { selector: "#searchInput", key: "keywords.search_placeholder", attr: "placeholder" },
        { selector: ".tab-button:nth-of-type(1)", key: "keywords.tab_all" },
        { selector: ".tab-button:nth-of-type(2)", key: "keywords.tab_analytics" },
        { selector: ".tab-button:nth-of-type(3)", key: "keywords.tab_history" }
      ],
      "/static/monthly-seo-report.html": [
        { selector: ".hero-title", key: "monthly.hero_title" },
        { selector: ".hero-subtitle", key: "monthly.hero_subtitle" },
        { selector: "#siteSelect option[value='']", key: "common.site_select_option" },
        { selector: ".toolbar button[onclick='loadReport()']", key: "monthly.load_report" },
        { selector: ".toolbar button.btn-success[onclick='downloadPdf()']", key: "monthly.download_pdf" }
      ]
    };

    var rules = pages[path] || [];
    rules.forEach(function (rule) {
      var el = document.querySelector(rule.selector);
      if (!el) return;
      if (rule.attr) {
        el.setAttribute(rule.attr, t(rule.key, el.getAttribute(rule.attr) || ""));
      } else {
        el.textContent = t(rule.key, el.textContent || "");
      }
    });
  }

  function ensureLangSwitcher() {
    var existing = document.getElementById("langSwitcher");
    if (existing) return existing;

    var root = document.createElement("div");
    root.id = "langSwitcher";
    root.className = "lang-switcher";
    root.innerHTML = [
      '<button type="button" class="lang-btn" data-lang="tr">🇹🇷 <span data-i18n="lang.tr">Turkce</span></button>',
      '<button type="button" class="lang-btn" data-lang="en">🇬🇧 <span data-i18n="lang.en">English</span></button>'
    ].join("");
    document.body.appendChild(root);

    root.querySelectorAll(".lang-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        setLang(btn.getAttribute("data-lang"));
      });
    });
    return root;
  }

  function syncLangButtons() {
    var root = document.getElementById("langSwitcher");
    if (!root) return;
    root.querySelectorAll(".lang-btn").forEach(function (btn) {
      var active = btn.getAttribute("data-lang") === currentLang;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function ensureFooterStyles() {
    if (document.getElementById("globalFooterInlineStyles")) return;
    var style = document.createElement("style");
    style.id = "globalFooterInlineStyles";
    style.textContent = [
      ".global-footer{margin:42px auto 10px;max-width:1200px;border:1px solid #dbe3ee;border-radius:16px;background:linear-gradient(180deg,#fff 0%,#f8fbff 100%);padding:22px;}",
      ".global-footer-grid{display:grid;grid-template-columns:1.2fr 1fr 1fr;gap:16px;}",
      ".global-footer-brand h4{margin:0 0 8px 0;font-size:22px;}",
      ".global-footer-brand p{margin:0;color:#64748b;line-height:1.6;}",
      ".global-footer-col h5{margin:0 0 8px 0;font-size:14px;text-transform:uppercase;letter-spacing:.4px;color:#0f4c81;}",
      ".global-footer-col a{display:block;color:#334155;text-decoration:none;margin-bottom:7px;}",
      ".global-footer-col a:hover{color:#0f4c81;}",
      ".global-footer-bottom{border-top:1px solid #dbe3ee;margin-top:16px;padding-top:12px;color:#64748b;font-size:13px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;}",
      "@media (max-width:640px){.global-footer-grid{grid-template-columns:1fr;}}"
    ].join("");
    document.head.appendChild(style);
  }

  var mount = document.getElementById("appHeader");
  var path = window.location.pathname || "";
  var navItems = [
    { href: "/static/home.html", labelKey: "nav.home", carrySite: true },
    { href: "/static/guide.html", labelKey: "nav.guide", carrySite: true },
    {
      href: "#",
      labelKey: "nav.services",
      carrySite: false,
      children: [
        { href: "/static/health-dashboard.html", labelKey: "nav.health", carrySite: true },
        { href: "/static/keywords-dashboard.html", labelKey: "nav.keywords", carrySite: true },
        { href: "/static/advanced-dashboard.html", labelKey: "nav.advanced", carrySite: true }
      ]
    },
    { href: "/static/site-select.html", labelKey: "nav.sites", carrySite: false },
    { href: "/static/monthly-seo-report.html", labelKey: "nav.monthly", carrySite: true },
    { href: "/static/admin-users.html", labelKey: "nav.members", carrySite: false },
    { href: "/static/login.html", labelKey: "nav.login", carrySite: false }
  ];

  function isActive(href) {
    if (href === "/") return path === "/";
    return path.indexOf(href) === 0;
  }

  function getCurrentSiteId() {
    var params = new URLSearchParams(window.location.search || "");
    return params.get("site") || "";
  }

  function buildHref(item, siteId) {
    if (!item.carrySite || !siteId) return item.href;
    return item.href + "?site=" + encodeURIComponent(siteId);
  }

  function syncLinks(siteId) {
    var links = document.querySelectorAll("a[data-carry-site='1'][data-base-href]");
    links.forEach(function (link) {
      var baseHref = link.getAttribute("data-base-href");
      if (!baseHref) return;
      link.setAttribute(
        "href",
        siteId ? (baseHref + "?site=" + encodeURIComponent(siteId)) : baseHref
      );
    });
  }

  function renderHeader() {
    if (!mount) return;
    mount.innerHTML = [
      '<header class="app-header">',
      '  <div class="app-header-inner">',
      '    <a class="app-brand" href="/static/home.html">GSC Radar</a>',
      '    <nav class="app-nav">',
      navItems
        .map(function (item) {
          if (item.children && item.children.length) {
            var childHtml = item.children.map(function (child) {
              var childHref = buildHref(child, getCurrentSiteId());
              var childCarry = child.carrySite ? "1" : "0";
              var childCls = "app-submenu-link" + (isActive(child.href) ? " active" : "");
              return (
                '<a class="' + childCls + '" data-base-href="' + child.href + '" data-carry-site="' + childCarry + '" href="' + childHref + '">' +
                t(child.labelKey, child.labelKey) +
                "</a>"
              );
            }).join("");
            var dropActive = item.children.some(function (c) { return isActive(c.href); });
            var dropCls = "app-nav-dropdown" + (dropActive ? " active" : "");
            return (
              '<div class="' + dropCls + '">' +
              '<button type="button" class="app-nav-link app-nav-toggle" data-dropdown-toggle="1" aria-expanded="' + (dropActive ? "true" : "false") + '">' +
              '<span>' + t(item.labelKey, item.labelKey) + '</span>' +
              '<span class="app-nav-caret" aria-hidden="true">▾</span>' +
              "</button>" +
              '<div class="app-submenu">' + childHtml + "</div>" +
              "</div>"
            );
          }
          var cls = "app-nav-link" + (isActive(item.href) ? " active" : "");
          var href = buildHref(item, getCurrentSiteId());
          var carry = item.carrySite ? "1" : "0";
          return (
            '<a class="' + cls + '" data-base-href="' + item.href + '" data-carry-site="' + carry + '" href="' + href + '">' +
            t(item.labelKey, item.labelKey) +
            "</a>"
          );
        })
        .join(""),
      "    </nav>",
      "  </div>",
      "</header>"
    ].join("");
    bindNavDropdownHandlers();
  }

  function bindNavDropdownHandlers() {
    var toggles = document.querySelectorAll(".app-nav-toggle[data-dropdown-toggle='1']");
    toggles.forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        var dropdown = btn.closest(".app-nav-dropdown");
        if (!dropdown) return;
        var willOpen = !dropdown.classList.contains("open");
        document.querySelectorAll(".app-nav-dropdown.open").forEach(function (d) {
          if (d !== dropdown) d.classList.remove("open");
        });
        dropdown.classList.toggle("open", willOpen);
        btn.setAttribute("aria-expanded", willOpen ? "true" : "false");
      });
    });
  }

  function renderFooter() {
    var existing = document.getElementById("appGlobalFooter");
    if (existing) existing.remove();
    var siteId = getCurrentSiteId();
    var footer = document.createElement("footer");
    footer.id = "appGlobalFooter";
    footer.className = "global-footer";
    footer.innerHTML = [
      '<div class="global-footer-grid">',
      '  <div class="global-footer-brand">',
      "    <h4>GSC Radar</h4>",
      "    <p>" + t("footer.brand_desc", "SEO ekipleri ve ajanslar icin performans komuta merkezi.") + "</p>",
      "  </div>",
      '  <div class="global-footer-col">',
      "    <h5>" + t("footer.col_product", "Urun") + "</h5>",
      '    <a data-base-href="/static/health-dashboard.html" data-carry-site="1" href="' + buildHref({ href: "/static/health-dashboard.html", carrySite: true }, siteId) + '">' + t("footer.link_health", "Saglik Komuta Merkezi") + "</a>",
      '    <a data-base-href="/static/advanced-dashboard.html" data-carry-site="1" href="' + buildHref({ href: "/static/advanced-dashboard.html", carrySite: true }, siteId) + '">' + t("footer.link_growth", "Growth Tools") + "</a>",
      '    <a data-base-href="/static/keywords-dashboard.html" data-carry-site="1" href="' + buildHref({ href: "/static/keywords-dashboard.html", carrySite: true }, siteId) + '">' + t("footer.link_keywords", "Keyword Intelligence") + "</a>",
      '    <a data-base-href="/static/monthly-seo-report.html" data-carry-site="1" href="' + buildHref({ href: "/static/monthly-seo-report.html", carrySite: true }, siteId) + '">' + t("footer.link_report", "White-label Raporlama") + "</a>",
      '    <a data-base-href="/static/guide.html" data-carry-site="1" href="' + buildHref({ href: "/static/guide.html", carrySite: true }, siteId) + '">' + t("footer.link_guide", "Kullanim Rehberi") + "</a>",
      "  </div>",
      '  <div class="global-footer-col">',
      "    <h5>" + t("footer.col_start", "Hizli Baslangic") + "</h5>",
      '    <a href="/static/login.html">' + t("footer.link_trial", "Ucretsiz Deneme Baslat") + "</a>",
      '    <a href="/static/site-select.html">' + t("footer.link_site", "Site Aktivasyonu") + "</a>",
      '    <a data-base-href="/static/monthly-seo-report.html" data-carry-site="1" href="' + buildHref({ href: "/static/monthly-seo-report.html", carrySite: true }, siteId) + '">' + t("footer.link_report_demo", "Rapor Ornegi") + "</a>",
      "  </div>",
      "</div>",
      '<div class="global-footer-bottom">',
      "  <span>" + t("footer.copy_left", "© 2026 GSC Radar. Tum haklari saklidir.") + "</span>",
      "  <span>" + t("footer.copy_right", "SEO operasyonu icin hiz, netlik ve olculebilir etki.") + "</span>",
      "</div>"
    ].join("");
    document.body.appendChild(footer);
  }

  window.GSCRadarI18n = {
    t: t,
    setLang: setLang,
    getLang: function () { return currentLang; },
    apply: applyPageTranslations
  };

  window.GSCRadarHeader = {
    setSiteId: function (siteId) {
      syncLinks(siteId || "");
    }
  };

  document.documentElement.setAttribute("lang", currentLang);
  ensureFooterStyles();
  renderHeader();
  renderFooter();
  ensureLangSwitcher();
  applyPageTranslations();
  syncLangButtons();

  var originalPushState = history.pushState;
  history.pushState = function () {
    originalPushState.apply(history, arguments);
    syncLinks(getCurrentSiteId());
  };

  window.addEventListener("popstate", function () {
    syncLinks(getCurrentSiteId());
  });

  document.addEventListener("click", function (e) {
    var target = e.target;
    if (target && target.closest && target.closest(".app-nav-dropdown")) return;
    document.querySelectorAll(".app-nav-dropdown.open").forEach(function (d) {
      d.classList.remove("open");
      var btn = d.querySelector(".app-nav-toggle[data-dropdown-toggle='1']");
      if (btn) btn.setAttribute("aria-expanded", "false");
    });
  });

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    document.querySelectorAll(".app-nav-dropdown.open").forEach(function (d) {
      d.classList.remove("open");
      var btn = d.querySelector(".app-nav-toggle[data-dropdown-toggle='1']");
      if (btn) btn.setAttribute("aria-expanded", "false");
    });
  });

  syncLinks(getCurrentSiteId());
  document.body.classList.add("has-app-header");
})();
