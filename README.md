<div align="center">

<img src="app/src/main/res/mipmap-xxxhdpi/ic_launcher.png" alt="MEH VPN Logo" width="128" height="128" />

# MEH VPN (مِه)

**Ultra-Minimalist One-Tap Android VPN Client with a 4-Stage Anti-DPI Cascading Engine**  
**کلاینت فوق‌مینیمال و تک‌کلیده اندروید با موتور اتصال هوشمند ۴ مرحله‌ای ضد فیلترینگ (DPI)**

[![Platform](https://img.shields.io/badge/Platform-Android%20(API%2026%2B)-3DDC84?logo=android&logoColor=white)](#)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.x-7F52FF?logo=kotlin&logoColor=white)](#)
[![UI](https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?logo=jetpackcompose&logoColor=white)](#)
[![Package](https://img.shields.io/badge/Package-com.meh.vpn-00E676)](#)

[**🇬🇧 English**](#-english-documentation) • [**🇮🇷 توضیحات فارسی**](#-توضیحات-فارسی)

</div>

---

## 🇬🇧 English Documentation

### Overview
**MEH (`com.meh.vpn`)** is a lightweight, zero-configuration Android VPN client designed specifically for heavily restricted networks. Instead of overwhelming users with complex server lists, manual subscription imports, or protocol tweaking, **MEH** provides a single centered power button that automatically discovers, verifies, and establishes a working tunnel through a **4-stage cascading connection pipeline**.

### ✨ Key Features
- **True One-Tap Experience:** Ultra-clean dark interface featuring a single central power button. All connection states (`Off`, `Fetching Config...`, `Testing Config...`, `Aether Fallback...`, `Serverless Fallback...`, `SNI Spoof Fallback...`, `Connecting...`, `Connected`) and the active server country flag are displayed cleanly below the button.
- **4-Stage Cascading Connection Engine:** Automatically falls back through four distinct circumvention techniques if upstream servers are blocked or throttled.
- **Real End-to-End Internet Verification:** Never relies on fake TCP pings alone. Every candidate node is verified through an actual encrypted tunnel handshake and an HTTP `204 No Content` probe (`connectivitycheck.gstatic.com/generate_204` / `cp.cloudflare.com/generate_204`) before marking the VPN as connected.
- **Native Android `VpnService` Tunnel:** Captures device traffic via a local TUN interface with protective socket binding (`VpnService.protect()`) to prevent routing loops and DNS leaks.
- **No Registration or Login Required:** Works immediately out of the box with anonymous telemetry via Firebase Analytics.

---

### 🛡️ 4-Stage Cascading Connection Pipeline

When the user taps the connect button, **MEH** executes the following stages in order until real internet connectivity is verified:

#### Stage 1: V2Ray Config Aggregation (`VLESS` & `Trojan`)
- Fetches live community subscription feeds in parallel from multiple GitHub repositories (including `SoliSpirit/v2ray-configs`, `barry-far/V2ray-Configs`, `Epodonios/v2ray-configs`, `mahdibland/V2RayAggregator`, and `yebekhe/TVC`).
- Decodes Base64 and raw URI feeds, deduplicates nodes, performs fast parallel TCP latency sweeps, and tests the fastest nodes with a full TLS/WebSocket/gRPC VLESS or Trojan handshake + HTTP 204 check.

#### Stage 2: Aether Gateway Fallback ([`CluvexStudio/Aether`](https://github.com/CluvexStudio/Aether))
- Triggered automatically if Stage 1 configs fail or time out.
- Scans clean Cloudflare Anycast & MASQUE edge endpoints and applies **2-part TLS `ClientHello` SNI fragmentation** with `TCP_NODELAY` so stateful DPI middleboxes cannot reassemble the SNI hostname in a single packet.

#### Stage 3: Serverless-for-Iran Fallback ([`patterniha/Serverless-for-Iran`](https://github.com/patterniha/Serverless-for-Iran))
- Triggered automatically if both Stage 1 and Stage 2 are unreachable.
- Implements a **Serverless Xray `freedom` outbound** with **1-to-3 byte `tlshello` micro-fragmentation** (`length: "1-3"`, `interval: "5ms"`), slicing the TLS `ClientHello` record into tiny TCP segments across clean Anycast IPs without requiring a dedicated remote proxy server.

#### Stage 4: SNI-Spoofing Desync Fallback ([`patterniha/SNI-Spoofing`](https://github.com/patterniha/SNI-Spoofing))
- Triggered as the final fallback when aggressive DPI blocks standard fragmentation.
- Splits the TLS `ClientHello` record into **3 separate TLS application-layer records** right across the Server Name Indication (SNI) extension boundary (`Record 1: Header + Random`, `Record 2: First half of SNI`, `Record 3: Second half of SNI + CipherSuites`), blinding DPI signature matchers while remaining 100% RFC-compliant for the destination TLS server.

---

### 🏗️ Project Structure

```text
app/src/main/java/com/example/
├── MainActivity.kt                  # Edge-to-edge entry point & VpnService permission flow
├── data/
│   ├── GitHubSubscriptionAggregator.kt # Stage 1: Parallel GitHub V2Ray subscription fetcher
│   ├── V2RayParser.kt                  # VLESS, Trojan, Aether, Serverless & SNI-Spoof parser/JSON builder
│   ├── AetherGatewayEngine.kt          # Stage 2: CluvexStudio/Aether edge scanner & config builder
│   ├── PatternihaBypassEngine.kt       # Stage 3 & 4: Serverless-for-Iran & SNI-Spoofing engines
│   └── VpnPreferences.kt               # DataStore persistence for last verified working config
├── model/
│   └── V2RayConfig.kt                  # Domain models & ConnectionStage enum
├── vpn/
│   ├── MehVpnService.kt                # Foreground Android VpnService & TUN packet forwarder
│   └── V2RayOutboundClient.kt          # TLS/WS/Fragmentation socket engine & HTTP 204 verifier
└── ui/
    ├── MehScreen.kt                    # Minimalist RTL Jetpack Compose UI
    ├── VpnViewModel.kt                 # 4-stage cascading connection state machine
    └── theme/                          # Obsidian dark theme & bundled Vazirmatn Persian typography
```

### 🚀 Build & Run

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/meh-vpn.git
   cd meh-vpn
   ```
2. Build the debug APK with Gradle:
   ```bash
   ./gradlew assembleDebug
   ```
3. Run unit & Robolectric verification tests:
   ```bash
   ./gradlew :app:testDebugUnitTest
   ```

---

<div dir="rtl">

## 🇮🇷 توضیحات فارسی

### معرفی پروژه
اپلیکیشن **MEH (مِه)** با شناسه بسته `com.meh.vpn` یک کلاینت وی‌پی‌ان اندروید فوق‌سبک، بدون نیاز به تنظیمات پیچیده و طراحی‌شده ویژه شبکه‌های دارای فیلترینگ شدید (DPI) است. برخلاف برنامه‌هایی که کاربر را درگیر لیست‌های شلوغ سرور یا وارد کردن دستی کانفیگ می‌کنند، **MEH** تنها یک دکمه پاور در مرکز صفحه دارد که با لمس آن، به صورت خودکار از طریق یک **خط لوله ۴ مرحله‌ای هوشمند** به اینترنت آزاد متصل می‌شود.

### ✨ ویژگی‌های کلیدی
- **رابط کاربری فوق‌مینیمال و تک‌کلیده:** در داخل دایره مرکزی فقط آیکون پاور قرار دارد و تمامی وضعیت‌های اتصال (`خاموش`، `دریافت کانفیگ...`، `تست کانفیگ...`، `اتصال Aether...`، `اتصال Serverless...`، `اتصال SNI Spoof...`، `در حال اتصال...` و `متصل`) به همراه پرچم و نام کشور سرور، در بیرون و پایین دایره نمایش داده می‌شوند.
- **موتور اتصال آبشاری ۴ مرحله‌ای:** در صورت مسدود بودن یا عدم پاسخگویی یک روش، برنامه بدون نیاز به دخالت کاربر بلافاصله روش بعدی را تست و متصل می‌کند.
- **تست واقعی اینترنت (HTTP 204 Verification):** برنامه به پینگ ساده TCP اکتفا نمی‌کند؛ بلکه پیش از اعلام وضعیت «متصل»، ترافیک واقعی را از دل تونل عبور داده و پاسخ `HTTP 204` را بررسی می‌کند تا از باز بودن واقعی اینترنت اطمینان حاصل شود.
- **بدون نیاز به ثبت‌نام یا لاگین:** اجرای بلافاصله پس از نصب، همراه با فونت فارسی توکار **وزیرمتن (Vazirmatn)**.

---

### 🛡️ معماری اتصال ۴ مرحله‌ای (Cascading Pipeline)

هنگامی که دکمه اتصال را لمس می‌کنید، برنامه به ترتیب زیر عمل می‌کند:

#### مرحله ۱: دریافت و تست خودکار کانفیگ‌های V2Ray (`VLESS` و `Trojan`)
- دریافت همزمان و موازی جدیدترین کانفیگ‌ها از مخازن معتبر گیت‌هاب (`SoliSpirit/v2ray-configs`، `barry-far/V2ray-Configs`، `Epodonios/v2ray-configs`، `mahdibland/V2RayAggregator` و `yebekhe/TVC`).
- رمزگشایی لینک‌های Base64 و خام، حذف موارد تکراری، سنجش موازی پینگ TCP و تست واقعی اتصال روی سریع‌ترین سرورها.

#### مرحله ۲: روش جایگزین اول — [`CluvexStudio/Aether`](https://github.com/CluvexStudio/Aether)
- در صورتی که در مرحله اول کانفیگ فعالی یافت نشود یا متصل نشود، برنامه به صورت خودکار وارد موتور **Aether** می‌شود.
- این مرحله با اسکن آی‌پی‌های تمیز Anycast کلودفلر و اعمال **تکه‌تکه کردن دو بخشی بسته TLS ClientHello در مرز SNI**، سیستم تشخیص بسته عمیق (DPI) را دور می‌زند.

#### مرحله ۳: روش جایگزین دوم — [`patterniha/Serverless-for-Iran`](https://github.com/patterniha/Serverless-for-Iran)
- در صورت عدم اتصال مرحله دوم، برنامه به سراغ روش **Serverless-for-Iran** می‌رود.
- این روش بر پایه پروتکل `freedom` هسته Xray و **خردایش میکرو (Micro-Fragmentation) بسته‌های `tlshello` در ابعاد ۱ تا ۳ بایت** با وقفه زمانی کوتاه عمل می‌کند تا بدون نیاز به سرور واسط، فایروال وضعیت‌محور را دور بزند.

#### مرحله ۴: روش جایگزین سوم — [`patterniha/SNI-Spoofing`](https://github.com/patterniha/SNI-Spoofing)
- در صورت مسدود بودن تمامی روش‌های بالا، برنامه از تکنیک **SNI-Spoofing / Record Desynchronization** استفاده می‌کند.
- در این روش، پیام `ClientHello` در لایه رکورد TLS دقیقا از وسط نام دامنه (SNI) به **۳ رکورد مجزای TLS** شکسته می‌شود تا تجهیزات فیلترینگ قادر به استخراج نام دامنه نباشند، در حالی که سرور مقصد آن‌ها را به صورت استاندارد بازسازی می‌کند.

---

### 🛠️ تکنولوژی‌های استفاده‌شده
- **زبان برنامه‌نویسی:** Kotlin + Coroutines & StateFlow
- **رابط کاربری:** Jetpack Compose (Material Design 3) با تم تاریک اختصاصی Obsidian
- **هسته شبکه و تونل:** Android `VpnService` + سوکت‌های محافظت‌شده TLS/WebSocket و موتورهای Fragmentation / Desync
- **ذخیره‌سازی و تحلیل:** Jetpack DataStore + Firebase Analytics (`com.meh.vpn`)
- **تست و پایداری:** JUnit 4 + Robolectric

</div>
