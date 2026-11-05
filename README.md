# MEH VPN (مِه وی‌پی‌ان)

یک کلاینت مینیمال، سریع و هوشمند **V2Ray / Xray-core** برای اندروید، طراحی‌شده با **Kotlin** و **Jetpack Compose** که تنها با یک لمس، سالم‌ترین و پرسرعت‌ترین سرورها را به‌صورت خودکار دریافت، تست دو مرحله‌ای و به تونل سراسری دستگاه (`VpnService` + `tun2socks`) متصل می‌کند.

---

## ✨ ویژگی‌های کلیدی (Key Features)

### ۱. اتصال تک‌کلیکی هوشمند (One-Tap Smart Connect)
- **رابط کاربری فوق‌مینیمال (Obsidian Dark UI):** تنها یک دکمه پاور مرکزی با انیمیشن حلقه‌ی وضعیت و نمایش زنده مرحله فعلی (`دریافت لیست سرور ها` ← `تست سرور ها` ← `در حال اتصال` ← `متصل`) با فونت فارسی وزیرمتن (`Vazirmatn`).
- **دریافت موازی اشتراک‌ها از آینه‌های ضد فیلتر:** دریافت خودکار کانفیگ‌های به‌روز `VLESS` و `Trojan` از مخزن `SoliSpirit/v2ray-configs` از طریق چندین CDN موازی (`jsDelivr`، `Fastly`، `GCore` و `GitHub Raw`).
- **فیلترینگ دقیق کانفیگ‌های ناسازگار:** حذف خودکار کانفیگ‌های دارای `flow` ناسازگار (مانند `xtls-rprx-vision`)، `REALITY/pbk` یا رمزنگاری‌های غیر استاندارد پیش از شروع تست.

### ۲. بنچمارک و راستی‌آزمایی دو مرحله‌ای (Two-Stage Multi-Endpoint Verification)
1. **مرحله اول (غربالگری سریع موازی):** تست اولیه سرعت و اتصال واقعی سرورها با درخواست `HTTP 204` (`connectivitycheck.gstatic.com`).
2. **مرحله دوم (تأیید واقعی TLS 443 و شبکه‌های اجتماعی):** بررسی همزمان اتصال رمزنگاری‌شده‌ی `HTTPS/TLS 443` درون تانل به:
   - `www.google.com:443`
   - `i.instagram.com:443` (سرویس موبایل اینستاگرام)
   - `api.x.com:443` (سرویس X / توییتر)
   - `149.154.167.50:443` (دیتاسنتر تلگرام)
- **انتخاب استخر متنوع (`Diverse Server Pool`):** انتخاب ۶ سرور برتر از ساب‌نت‌ها (`/16`) و دامنه‌های SNI متنوع برای جلوگیری از محدودیت نرخ اتصال (Rate-Limiting) روی یک نود واحد.

### ۳. معماری شبکه، DNS و مدیریت استریم‌های HTTP/2
- **پاسخ آنی DNS (`Fake-IP First` + `Domain-First Routing`):**
  - پاسخ فوری به کوئری‌های `A` (`QTYPE=1`) با آدرس‌های پایدار عمومی (`198.54.x.y`) و نگاشت معکوس آن به دامنه اصلی در پروکسی محلی، به همراه استخراج دقیق `SNI` از پکت‌های `TLS ClientHello` (حتی در صورت جابه‌جایی ترتیب اکستنشن‌ها در Chrome/Cronet/BoringSSL یا تکه شدن پکت‌های بزرگ TLS 1.3 Post-Quantum) و هدر `Host` در HTTP (`destOverride: ["http", "tls"]`).
  - مسدودسازی تمیز کوئری‌های `AAAA` (`QTYPE=28`)، `HTTPS/SVCB` (`QTYPE=65/64`) و بسته‌های UDP پورت `443` (`QUIC / HTTP3`) تا اپلیکیشن‌هایی مانند **Instagram**، **X (Twitter)**، **YouTube** و **Chrome** بلافاصله و بدون مکث روی استریم‌های پایدار `TCP/443 (HTTP/2)` کار کنند.
  - پشتیبانی از رزولوشن واقعی DNS درون تانل (`Persistent DNS-over-TCP` و `DoH`) با سقف زمانی سخت‌گیرانه (`DNS_BUDGET_MS = 2500ms`) برای حالت‌های مستقیم.
- **رله‌ی شفاف و بدون قفل برای HTTP/2 و CDNها (`Transparent Non-Blocking TCP Relay`):**
  - ارسال بلافاصله‌ی `ClientHello` روی تانل و ورود مستقیم به حلقه‌ی دوطرفه‌ی `relayStreams` با بافرهای ۳۲ کیلوبایتی و تایم‌اوت پایدار ۳ دقیقه‌ای (`180_000ms`)، بدون قطع شدن کانکشن‌های مالتی‌پلکس‌شده‌ی HTTP/2 در هنگام اسکرول فید اینستاگرام و لود تصاویر و ویدیوهای CDN (`scontent-*.cdninstagram.com`).
- **پشتیبانی از اندروید ۵ تا ۱۶ (شامل اندروید ۹ / Samsung Conscrypt):**
  - پیاده‌سازی موتور `SSLEngine` روی استریم‌ها (`openSslEngineOverStreams`) و پشتیبانی از فرگمنتیشن `TLS ClientHello` (`GFW-knocker / Xray-core v26.10.3`) بدون کرش `FileDescriptor` در اندروید ۹.

---

## 🏗️ معماری پروژه (Project Structure)

```text
app/src/main/java/com/example/
├── MainActivity.kt                 # رابط کاربری Jetpack Compose (دکمه پاور، انیمیشن وضعیت و لاگ زنده)
├── data/
│   └── SoliSpiritRepository.kt     # دریافت موازی اشتراک‌ها و بنچمارک دو مرحله‌ای سرورها
├── model/
│   └── V2RayConfig.kt              # مدل داده و پارسر لینک‌های vless:// ، mvless:// ، jvless:// و trojan://
├── telemetry/
│   └── MehTelemetry.kt             # ثبت رویدادها و خطاهای چرخه اتصال
├── ui/
│   ├── MehViewModel.kt             # مدیریت وضعیت اتصال (DISCONNECTED, FETCHING, TESTING, CONNECTING, CONNECTED, ERROR)
│   └── theme/                      # پالت رنگی Obsidian و تایپوگرافی Vazirmatn
└── vpn/
    ├── MehVpnService.kt            # سرویس VPN اندروید، راه‌اندازی رابط TUN و موتور بومی Go tun2socks
    ├── LocalV2RayProxyServer.kt    # سرور محلی SOCKS5 (TCP + UDP ASSOCIATE) و HTTP CONNECT با SNI Sniffing و DNS
    ├── V2RayOutboundClient.kt      # کلاینت پروتکل‌های VLESS و Trojan روی TCP، WebSocket و HTTPUpgrade
    └── GfwKnockerXrayCore.kt       # استخراج‌کننده TLS SNI، موتور SSLEngine و فرگمنتیشن پکت‌های TLS/TCP
```

---

## 🚀 نحوه ساخت و اجرا (Build & Test)

### پیش‌نیازها
- **JDK 21**
- **Android SDK (API 36)**

### کامپایل نسخه دیباگ (APK)
```bash
gradle :app:assembleDebug
```

### اجرای تست‌های واحد و شبیه‌سازی ترافیک تونل
```bash
gradle :app:testDebugUnitTest
```

---

## 🔒 مجوزها و حریم خصوصی (Permissions)
- `android.permission.INTERNET` و `android.permission.ACCESS_NETWORK_STATE`: برای دریافت لیست سرورها و برقراری تانل رمزنگاری‌شده.
- `android.permission.FOREGROUND_SERVICE` و `android.permission.FOREGROUND_SERVICE_SPECIAL_USE`: برای فعال نگه‌داشتن سرویس `VpnService` در پس‌زمینه همراه با اعلان وضعیت اتصال.
- ترافیک اپلیکیشن خودِ `MEH` از طریق `addDisallowedApplication(packageName)` و `VpnService.protect(socket)` از تانل مستثنی می‌شود تا حلقه بازگشتی (Loopback) ایجاد نشود.
