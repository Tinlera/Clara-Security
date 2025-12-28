# 🛡️ CLARA Security - Tasarım Spesifikasyonu v2.0

## 📋 Proje Özeti

**CLARA** - Comprehensive Layered Autonomous Response Architecture

| Özellik | Değer |
|---------|-------|
| **Platform** | Android 15 (API 36) |
| **Hedef Cihaz** | Poco X7 Pro (RODIN) |
| **Root** | KernelSU Next |
| **Mimari** | Mikro-servis Daemon + Native Android App |
| **Tema** | Dark Cyberpunk / Hacker |
| **AI** | Önce kural tabanlı, sonra TFLite |

---

## 🏗️ Mikro-Servis Mimarisi

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CLARA SECURITY SYSTEM v2.0                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                     ANDROID APP (Kotlin)                           │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │ │
│  │  │Dashboard │  │ Scanner  │  │ Privacy  │  │ Settings │           │ │
│  │  │  Screen  │  │  Screen  │  │Dashboard │  │  Screen  │           │ │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │ │
│  │       └──────────────┴──────────────┴──────────────┘               │ │
│  │                              │                                      │ │
│  │                        AIDL / Binder IPC                           │ │
│  └──────────────────────────────┼─────────────────────────────────────┘ │
│                                 │                                        │
│  ┌──────────────────────────────┴─────────────────────────────────────┐ │
│  │                     ORCHESTRATOR DAEMON                             │ │
│  │  ┌─────────────────────────────────────────────────────────────┐   │ │
│  │  │  Service Discovery │ Health Monitor │ Event Router │ IPC   │   │ │
│  │  └─────────────────────────────────────────────────────────────┘   │ │
│  └──────────────────────────────┬─────────────────────────────────────┘ │
│                                 │                                        │
│            ┌────────────────────┼────────────────────┐                  │
│            │                    │                    │                  │
│  ┌─────────▼─────────┐ ┌───────▼───────┐ ┌─────────▼─────────┐        │
│  │   SECURITY CORE   │ │ PRIVACY CORE  │ │   APP MANAGER     │        │
│  │                   │ │               │ │                   │        │
│  │ • SMS Monitor     │ │ • Tracker     │ │ • App Lock        │        │
│  │ • File Scanner    │ │   Blocker     │ │ • Root Hider      │        │
│  │ • Network Monitor │ │ • Permission  │ │ • Permission      │        │
│  │ • WhatsApp/TG     │ │   Watcher     │ │   Monitor         │        │
│  │ • Keylogger Det.  │ │ • Privacy     │ │                   │        │
│  │                   │ │   Dashboard   │ │                   │        │
│  └─────────┬─────────┘ └───────┬───────┘ └─────────┬─────────┘        │
│            │                   │                   │                   │
│  ┌─────────▼───────────────────▼───────────────────▼─────────┐        │
│  │                     SHARED SERVICES                        │        │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │        │
│  │  │    AI    │  │ Database │  │  Logger  │  │  Config  │  │        │
│  │  │  Engine  │  │  (SQLite)│  │ (Syslog) │  │  Manager │  │        │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │        │
│  └───────────────────────────────────────────────────────────┘        │
│                                                                        │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                     VPN SERVICE (Opsiyonel)                     │   │
│  │     Firewall │ DNS-over-HTTPS │ Traffic Filter │ Ad Block      │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🎨 UI Tasarım Sistemi - Dark Cyberpunk

### Renk Paleti

```css
/* Ana Renkler */
--bg-primary: #0a0a0a;      /* Derin siyah */
--bg-secondary: #0f0f0f;    /* Koyu gri */
--bg-card: #1a1a1a;         /* Kart arka planı */
--bg-card-glass: rgba(26, 26, 26, 0.7);  /* Glassmorphism */

/* Neon Aksanlar */
--neon-green: #00ff41;      /* Matrix yeşili - Başarı */
--neon-cyan: #00d4ff;       /* Siyan - Bilgi */
--neon-red: #ff0040;        /* Kırmızı - Tehdit */
--neon-yellow: #ffaa00;     /* Sarı - Uyarı */
--neon-purple: #9d00ff;     /* Mor - Özel */

/* Metin */
--text-primary: #e0e0e0;    /* Ana metin */
--text-secondary: #808080;  /* İkincil metin */
--text-terminal: #00ff41;   /* Terminal metni */

/* Glow Efektleri */
--glow-green: 0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 30px #00ff41;
--glow-cyan: 0 0 10px #00d4ff, 0 0 20px #00d4ff;
--glow-red: 0 0 10px #ff0040, 0 0 20px #ff0040;
```

### Tipografi

```css
/* Başlıklar - Futuristik */
--font-display: 'Orbitron', 'Share Tech Mono', monospace;

/* Gövde - Okunabilir */
--font-body: 'Roboto Mono', 'JetBrains Mono', monospace;

/* Terminal */
--font-terminal: 'Fira Code', 'Source Code Pro', monospace;

/* Boyutlar */
--text-xs: 10sp;
--text-sm: 12sp;
--text-base: 14sp;
--text-lg: 16sp;
--text-xl: 20sp;
--text-2xl: 24sp;
--text-3xl: 32sp;
```

### Bileşen Stilleri

```
┌─────────────────────────────────────────────────────────────────┐
│  SECURITY SCORE GAUGE                                           │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    ╭──────────────╮                        │  │
│  │                 ╭──╯      94      ╰──╮                     │  │
│  │              ╭──╯                    ╰──╮                  │  │
│  │             ╱                            ╲                 │  │
│  │            │    ████████████████░░░░     │                 │  │
│  │             ╲                            ╱                 │  │
│  │              ╰──╮                    ╭──╯                  │  │
│  │                 ╰──╮  PROTECTED  ╭──╯                      │  │
│  │                    ╰──────────────╯                        │  │
│  │           Neon green outer ring with glow                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  STATUS CARDS                                                    │
│  ┌──────────────────┐  ┌──────────────────┐                     │
│  │ ░░░░░░░░░░░░░░░░ │  │ ░░░░░░░░░░░░░░░░ │                     │
│  │ ┌──────────────┐ │  │ ┌──────────────┐ │                     │
│  │ │ 📱 SMS       │ │  │ │ 📁 FILES    │ │                     │
│  │ │ 3 blocked   │ │  │ │ 0 threats   │ │                     │
│  │ │             │ │  │ │             │ │                     │
│  │ └──────────────┘ │  │ └──────────────┘ │                     │
│  │  Neon border     │  │  Neon border     │                     │
│  └──────────────────┘  └──────────────────┘                     │
│  Glassmorphism + subtle scan lines                               │
│                                                                  │
│  TERMINAL LOG                                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ > [00:24:15] SMS scanned: +90532*** - SAFE              │  │
│  │ > [00:24:12] File detected: download.apk - SCANNING...  │  │
│  │ > [00:24:10] Network: 47 connections active             │  │
│  │ > [00:24:08] Tracker blocked: facebook.analytics.com    │  │
│  │ █                                                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│  Green text on black, monospace font, blinking cursor           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 Seçilen Özellikler

### Çekirdek Güvenlik (Security Core)

| # | Özellik | Açıklama | Öncelik |
|---|---------|----------|---------|
| **1** | WhatsApp/Telegram İzleme | Mesajlardaki URL'leri tara, phishing tespit | P0 |
| **SMS** | SMS Monitor | Phishing SMS tespiti (mevcut) | P0 |
| **FILE** | File Scanner | Malware/APK tarama (mevcut) | P0 |
| **NET** | Network Monitor | Bağlantı izleme (mevcut) | P0 |
| **6** | Keylogger Detector | Accessibility kötüye kullanan uygulamalar | P1 |

### Gizlilik (Privacy Core)

| # | Özellik | Açıklama | Öncelik |
|---|---------|----------|---------|
| **5** | Permission Watcher | İzin kullanımını logla ve raporla | P0 |
| **11** | Tracker Blocker | Host dosyası ile reklam/tracker engelle | P1 |
| **12** | Privacy Dashboard | İzin kullanım istatistikleri UI | P0 |

### Uygulama Yönetimi (App Manager)

| # | Özellik | Açıklama | Öncelik |
|---|---------|----------|---------|
| **2** | Uygulama Kilidi | PIN/Biyometrik ile uygulama kilitle | P1 |
| **19** | Root Hider | Root algılayan uygulamalardan gizle | P2 |

### Opsiyonel (VPN Service)

| # | Özellik | Açıklama | Öncelik |
|---|---------|----------|---------|
| **15** | VPN Entegrasyonu | Trafik filtreleme, firewall | P3 |

---

## 🔧 Mikro-Servis Detayları

### 1. Orchestrator Daemon
```cpp
// Ana koordinatör - diğer servisleri yönetir
class Orchestrator {
    // Servis keşfi
    void discoverServices();
    
    // Sağlık kontrolü
    void healthCheck();
    
    // Event routing
    void routeEvent(Event e);
    
    // IPC yönetimi
    void handleIPC();
};
```

### 2. Security Core Daemon
```cpp
// Güvenlik tarama servisi
class SecurityCore {
    SmsMonitor sms;
    FileMonitor file;
    NetworkMonitor net;
    MessengerMonitor messenger;  // WhatsApp/Telegram
    KeyloggerDetector keylogger;
    
    void scan();
    void onThreat(Threat t);
};
```

### 3. Privacy Core Daemon
```cpp
// Gizlilik servisi
class PrivacyCore {
    TrackerBlocker tracker;
    PermissionWatcher permission;
    
    vector<PermissionUsage> getUsageStats();
    int getTrackerBlockCount();
};
```

### 4. App Manager Daemon
```cpp
// Uygulama yönetim servisi
class AppManager {
    AppLock appLock;
    RootHider rootHider;
    
    void lockApp(string package);
    void hideFromApp(string package);
};
```

### 5. VPN Service (Opsiyonel)
```cpp
// VPN tabanlı trafik filtreleme
class VpnService {
    Firewall firewall;
    DnsOverHttps doh;
    AdBlocker adblock;
    
    void startVpn();
    void addFirewallRule(Rule r);
};
```

---

## 📁 Proje Dosya Yapısı (Güncellenmiş)

```
clara_security/
├── daemon/
│   ├── orchestrator/           # Ana koordinatör
│   │   ├── src/
│   │   └── include/
│   │
│   ├── security_core/          # Güvenlik servisi
│   │   ├── src/
│   │   │   ├── sms_monitor.cpp
│   │   │   ├── file_monitor.cpp
│   │   │   ├── network_monitor.cpp
│   │   │   ├── messenger_monitor.cpp
│   │   │   └── keylogger_detector.cpp
│   │   └── include/
│   │
│   ├── privacy_core/           # Gizlilik servisi
│   │   ├── src/
│   │   │   ├── tracker_blocker.cpp
│   │   │   └── permission_watcher.cpp
│   │   └── include/
│   │
│   ├── app_manager/            # Uygulama yönetimi
│   │   ├── src/
│   │   │   ├── app_lock.cpp
│   │   │   └── root_hider.cpp
│   │   └── include/
│   │
│   ├── vpn_service/            # Opsiyonel VPN
│   │   └── ...
│   │
│   └── shared/                 # Ortak kütüphaneler
│       ├── ai_engine/
│       ├── database/
│       ├── config/
│       └── ipc/
│
├── app/                        # Android App (Kotlin)
│   ├── src/main/
│   │   ├── java/com/clara/security/
│   │   │   ├── ui/
│   │   │   │   ├── dashboard/
│   │   │   │   ├── scanner/
│   │   │   │   ├── privacy/
│   │   │   │   └── settings/
│   │   │   ├── service/
│   │   │   ├── receiver/
│   │   │   └── util/
│   │   ├── res/
│   │   │   ├── layout/
│   │   │   ├── drawable/
│   │   │   ├── values/
│   │   │   └── font/
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts
│
├── module/                     # KernelSU modülü
│   ├── module.prop
│   ├── service.sh
│   ├── post-fs-data.sh
│   ├── sepolicy.rule
│   └── system/
│       ├── bin/               # Daemon'lar
│       └── etc/clara/         # Config, models
│
├── models/                     # AI modelleri (ileride)
│   ├── sms_phishing.tflite
│   ├── malware_classifier.tflite
│   └── network_anomaly.tflite
│
└── scripts/
    ├── build_android.sh
    ├── build_app.sh
    └── package_module.sh
```

---

## 🚀 Geliştirme Yol Haritası

### Faz 1: Temel Altyapı (Hafta 1-2)
- [x] Proje yapısı
- [x] Daemon iskelet kodu
- [ ] Mikro-servis IPC altyapısı
- [ ] Orchestrator daemon
- [ ] SQLite database

### Faz 2: Çekirdek Güvenlik (Hafta 3-4)
- [x] SMS Monitor (kural tabanlı)
- [x] File Monitor (inotify + hash)
- [x] Network Monitor
- [ ] WhatsApp/Telegram Monitor
- [ ] Keylogger Detector

### Faz 3: Gizlilik Özellikleri (Hafta 5-6)
- [ ] Permission Watcher
- [ ] Tracker Blocker (hosts dosyası)
- [ ] Privacy Dashboard veri toplama

### Faz 4: Android App (Hafta 7-9)
- [ ] Kotlin proje kurulumu
- [ ] Dashboard UI (Cyberpunk tema)
- [ ] Scanner UI
- [ ] Privacy Dashboard UI
- [ ] Settings UI
- [ ] AIDL ile daemon bağlantısı

### Faz 5: Ek Özellikler (Hafta 10-12)
- [ ] App Lock
- [ ] Root Hider
- [ ] Bildirim sistemi
- [ ] Widget

### Faz 6: VPN & Polish (Hafta 13+)
- [ ] VPN Service (opsiyonel)
- [ ] AI modelleri entegrasyonu
- [ ] Performance optimizasyonu
- [ ] Beta test

---

## 📱 Ekran Akışı

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Splash     │────▶│  Dashboard   │────▶│   Scanner    │
│   Screen     │     │              │     │              │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
                            ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Privacy    │◀────│  Navigation  │────▶│   Settings   │
│  Dashboard   │     │     Bar      │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
        │                                         │
        ▼                                         ▼
┌──────────────┐                         ┌──────────────┐
│   App Lock   │                         │  Root Hider  │
│   Manager    │                         │   Config     │
└──────────────┘                         └──────────────┘
```

---

## 🎯 Öncelik Matrisi

```
        YÜKSEK ETKİ
             │
    P0 ──────┼────── P1
    SMS Mon  │  WhatsApp Mon
    File Mon │  Keylogger Det.
    Network  │  Tracker Block
    Perm Wat │  App Lock
    Privacy  │
             │
  ───────────┼───────────▶ DÜŞÜK ÇABA → YÜKSEK ÇABA
             │
    P2 ──────┼────── P3
    Root Hid │  VPN Service
             │  AI Models
             │
        DÜŞÜK ETKİ
```

---

*CLARA Security v2.0 - Dark Cyberpunk Edition*
*"Your Digital Guardian in the Shadows"*
