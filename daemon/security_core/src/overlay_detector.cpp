/**
 * CLARA Security - Overlay Attack Detector Implementation
 */

#include "../include/overlay_detector.h"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <regex>
#include <sstream>
#include <syslog.h>
#include <thread>
#include <unistd.h>

namespace clara {

// Varsayılan whitelist (güvenli overlay uygulamaları)
static const std::vector<std::string> DEFAULT_WHITELIST = {
    "com.android.systemui",
    "com.google.android.inputmethod.latin", // Gboard
    "com.samsung.android.honeyboard",       // Samsung klavye
    "com.miui.securitycenter",              // MIUI güvenlik
    "com.facebook.orca",                    // Messenger chat heads
    "com.google.android.apps.messaging",    // Google Messages
};

// Hassas uygulamalar (banka, ödeme, kripto vb.)
static const std::unordered_map<std::string, SensitiveAppCategory>
    SENSITIVE_APPS = {
        // Türk Bankaları
        {"com.garanti.cepsubesi", SensitiveAppCategory::BANKING},
        {"com.akbank.android.apps.akbank_direkt",
         SensitiveAppCategory::BANKING},
        {"com.ykb.android", SensitiveAppCategory::BANKING},
        {"com.vakifbank.mobile", SensitiveAppCategory::BANKING},
        {"com.ziraat.ziraatmobil", SensitiveAppCategory::BANKING},
        {"tr.com.sekerbilisim.mbanking", SensitiveAppCategory::BANKING},
        {"com.finansbank.mobile.cepsube", SensitiveAppCategory::BANKING},
        {"com.teb", SensitiveAppCategory::BANKING},
        {"com.ingbanktr.ingmobil", SensitiveAppCategory::BANKING},
        {"com.denizbank.mobildeniz", SensitiveAppCategory::BANKING},
        {"com.htsu.hsbcpersonalbanking", SensitiveAppCategory::BANKING},
        {"com.kuveytturk.mobil", SensitiveAppCategory::BANKING},
        {"com.magiclick.odeabank", SensitiveAppCategory::BANKING},

        // Global Bankalar
        {"com.chase.sig.android", SensitiveAppCategory::BANKING},
        {"com.wf.wellsfargomobile", SensitiveAppCategory::BANKING},
        {"com.infonow.bofa", SensitiveAppCategory::BANKING},
        {"com.citi.citimobile", SensitiveAppCategory::BANKING},
        {"com.usbank.mobilebanking", SensitiveAppCategory::BANKING},
        {"com.cba.android.netbank", SensitiveAppCategory::BANKING},
        {"uk.co.hsbc.hsbcukmobilebanking", SensitiveAppCategory::BANKING},
        {"com.barclays.android.barclaysmobilebanking",
         SensitiveAppCategory::BANKING},

        // Ödeme Uygulamaları
        {"com.google.android.apps.walletnfcrel", SensitiveAppCategory::PAYMENT},
        {"com.samsung.android.spay", SensitiveAppCategory::PAYMENT},
        {"com.paypal.android.p2pmobile", SensitiveAppCategory::PAYMENT},
        {"com.venmo", SensitiveAppCategory::PAYMENT},
        {"com.squareup.cash", SensitiveAppCategory::PAYMENT},
        {"com.iyzico.app", SensitiveAppCategory::PAYMENT},
        {"com.papara.app", SensitiveAppCategory::PAYMENT},
        {"com.tosla.app", SensitiveAppCategory::PAYMENT},

        // Kripto Cüzdanlar
        {"com.coinbase.android", SensitiveAppCategory::CRYPTO},
        {"com.binance.dev", SensitiveAppCategory::CRYPTO},
        {"io.metamask", SensitiveAppCategory::CRYPTO},
        {"com.wallet.crypto.trustapp", SensitiveAppCategory::CRYPTO},
        {"com.krakenfutures.app", SensitiveAppCategory::CRYPTO},
        {"com.btcturk", SensitiveAppCategory::CRYPTO},
        {"com.paribu.app", SensitiveAppCategory::CRYPTO},

        // Şifre Yöneticileri
        {"com.lastpass.lpandroid", SensitiveAppCategory::PASSWORD},
        {"com.x8bit.bitwarden", SensitiveAppCategory::PASSWORD},
        {"com.agilebits.onepassword", SensitiveAppCategory::PASSWORD},
        {"com.dashlane", SensitiveAppCategory::PASSWORD},
        {"keepass2android.keepass2android", SensitiveAppCategory::PASSWORD},

        // 2FA Uygulamaları
        {"com.google.android.apps.authenticator2",
         SensitiveAppCategory::AUTHENTICATOR},
        {"com.authy.authy", SensitiveAppCategory::AUTHENTICATOR},
        {"com.microsoft.msa.authenticator",
         SensitiveAppCategory::AUTHENTICATOR},
        {"org.fedorahosted.freeotp", SensitiveAppCategory::AUTHENTICATOR},

        // E-posta (login için)
        {"com.google.android.gm", SensitiveAppCategory::EMAIL},
        {"com.microsoft.office.outlook", SensitiveAppCategory::EMAIL},
        {"com.yahoo.mobile.client.android.mail", SensitiveAppCategory::EMAIL},
};

OverlayDetector::OverlayDetector() : running_(false) {
  syslog(LOG_INFO, "OverlayDetector oluşturuluyor...");
}

OverlayDetector::~OverlayDetector() { stop(); }

bool OverlayDetector::initialize() {
  syslog(LOG_INFO, "OverlayDetector başlatılıyor...");

  // Whitelist yükle
  loadWhitelist();

  // Hassas uygulamaları yükle
  loadSensitiveApps();

  // İlk taramayı yap
  scan();

  return true;
}

void OverlayDetector::stop() {
  running_ = false;
  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }
  syslog(LOG_INFO, "OverlayDetector durduruldu");
}

std::string OverlayDetector::executeCommand(const std::string &cmd) {
  std::string result;
  FILE *pipe = popen(cmd.c_str(), "r");
  if (pipe) {
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
      result += buffer;
    }
    pclose(pipe);
  }
  return result;
}

int OverlayDetector::scan() {
  syslog(LOG_DEBUG, "Overlay taraması yapılıyor...");

  int suspicious_count = 0;
  auto overlay_apps = getOverlayApps();
  auto active_overlays = getActiveOverlays();
  std::string foreground = getForegroundApp();
  bool foreground_sensitive = isSensitiveApp(foreground);

  stats_.total_overlay_apps = overlay_apps.size();
  stats_.active_overlays = active_overlays.size();
  stats_.last_scan_time =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  for (const auto &app : active_overlays) {
    // Whitelist kontrolü
    if (whitelist_.count(app.package_name) > 0 || app.is_whitelisted) {
      continue;
    }

    // Sistem uygulaması kontrolü
    if (app.is_system_app) {
      continue;
    }

    // Tehdit seviyesi değerlendir
    OverlayThreatLevel threat = assessThreat(app);

    // Hassas uygulama üzerinde overlay varsa CRITICAL
    if (foreground_sensitive && app.is_currently_drawing) {
      threat = OverlayThreatLevel::CRITICAL;
      syslog(LOG_ALERT, "KRİTİK: %s hassas uygulama üzerinde overlay çiziyor!",
             app.package_name.c_str());
    }

    if (threat >= OverlayThreatLevel::MEDIUM) {
      suspicious_count++;

      if (threat_callback_) {
        threat_callback_(app, threat);
      }

      // CRITICAL ise otomatik engelle
      if (threat == OverlayThreatLevel::CRITICAL) {
        revokeOverlayPermission(app.package_name);
        stats_.blocked_count++;
      }
    }
  }

  return suspicious_count;
}

std::vector<OverlayAppInfo> OverlayDetector::getOverlayApps() {
  std::vector<OverlayAppInfo> apps;

  // appops ile SYSTEM_ALERT_WINDOW izni olan uygulamaları bul
  std::string result =
      executeCommand("appops query-op SYSTEM_ALERT_WINDOW allow 2>/dev/null");

  std::istringstream stream(result);
  std::string line;

  while (std::getline(stream, line)) {
    if (line.empty())
      continue;

    // Paket adını temizle
    std::string pkg = line;
    pkg.erase(0, pkg.find_first_not_of(" \t\n\r"));
    pkg.erase(pkg.find_last_not_of(" \t\n\r") + 1);

    if (pkg.empty() || pkg[0] == '#')
      continue;

    OverlayAppInfo info;
    info.package_name = pkg;
    info.has_overlay_permission = true;
    info.is_currently_drawing = false;
    info.is_system_app =
        (pkg.find("com.android.") == 0 ||
         pkg.find("com.google.android.") == 0 || pkg.find("com.miui.") == 0);
    info.is_whitelisted = (whitelist_.count(pkg) > 0);
    info.overlay_count = 0;
    info.last_overlay_time = 0;

    apps.push_back(info);
  }

  return apps;
}

std::vector<OverlayAppInfo> OverlayDetector::getActiveOverlays() {
  std::vector<OverlayAppInfo> active;

  // dumpsys window ile aktif overlay'leri bul
  std::string result =
      executeCommand("dumpsys window windows 2>/dev/null | grep -E "
                     "'mSurface|mOwnerPackage' | head -50");

  std::unordered_set<std::string> active_packages;
  std::istringstream stream(result);
  std::string line;
  std::regex pkg_regex("mOwnerPackage=([^\\s]+)");

  while (std::getline(stream, line)) {
    std::smatch match;
    if (std::regex_search(line, match, pkg_regex)) {
      std::string pkg = match[1].str();

      // Sistem UI ve launcher hariç
      if (pkg != "com.android.systemui" &&
          pkg.find("launcher") == std::string::npos) {
        active_packages.insert(pkg);
      }
    }
  }

  // Aktif overlay bilgilerini oluştur
  for (const auto &pkg : active_packages) {
    OverlayAppInfo info;
    info.package_name = pkg;
    info.has_overlay_permission = true;
    info.is_currently_drawing = true;
    info.is_system_app = (pkg.find("com.android.") == 0);
    info.is_whitelisted = (whitelist_.count(pkg) > 0);
    info.last_overlay_time =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    active.push_back(info);

    // Geçmişe ekle
    overlay_history_[pkg] = info;
  }

  return active;
}

bool OverlayDetector::hasOverlayPermission(const std::string &package_name) {
  std::string cmd =
      "appops get " + package_name + " SYSTEM_ALERT_WINDOW 2>/dev/null";
  std::string result = executeCommand(cmd);
  return result.find("allow") != std::string::npos;
}

std::string OverlayDetector::getForegroundApp() {
  std::string result = executeCommand("dumpsys activity activities 2>/dev/null "
                                      "| grep 'mResumedActivity' | head -1");

  std::regex pkg_regex("u0 ([^/]+)/");
  std::smatch match;

  if (std::regex_search(result, match, pkg_regex)) {
    return match[1].str();
  }

  return "";
}

bool OverlayDetector::isSensitiveApp(const std::string &package_name) {
  return sensitive_apps_.count(package_name) > 0;
}

void OverlayDetector::addToWhitelist(const std::string &package_name) {
  whitelist_.insert(package_name);
  saveWhitelist();
  stats_.whitelisted_count = whitelist_.size();
  syslog(LOG_INFO, "Whitelist'e eklendi: %s", package_name.c_str());
}

void OverlayDetector::removeFromWhitelist(const std::string &package_name) {
  whitelist_.erase(package_name);
  saveWhitelist();
  stats_.whitelisted_count = whitelist_.size();
  syslog(LOG_INFO, "Whitelist'ten çıkarıldı: %s", package_name.c_str());
}

void OverlayDetector::setThreatCallback(ThreatCallback callback) {
  threat_callback_ = callback;
}

bool OverlayDetector::revokeOverlayPermission(const std::string &package_name) {
  syslog(LOG_WARNING, "Overlay izni kaldırılıyor: %s", package_name.c_str());

  // appops ile izni kapat
  std::string cmd = "appops set " + package_name + " SYSTEM_ALERT_WINDOW deny";
  executeCommand(cmd);

  // Eğer app hala çiziyorsa, force stop
  auto active = getActiveOverlays();
  for (const auto &app : active) {
    if (app.package_name == package_name) {
      executeCommand("am force-stop " + package_name);
      break;
    }
  }

  return true;
}

OverlayDetector::Stats OverlayDetector::getStats() const { return stats_; }

void OverlayDetector::startMonitoring(int interval_ms) {
  if (running_)
    return;

  running_ = true;
  monitor_thread_ =
      std::thread(&OverlayDetector::monitorLoop, this, interval_ms);
  syslog(LOG_INFO, "Overlay izleme başlatıldı (interval: %dms)", interval_ms);
}

void OverlayDetector::monitorLoop(int interval_ms) {
  while (running_) {
    checkOverlays();
    std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
  }
}

void OverlayDetector::checkOverlays() {
  int suspicious = scan();
  if (suspicious > 0) {
    syslog(LOG_WARNING, "%d şüpheli overlay tespit edildi", suspicious);
  }
}

OverlayThreatLevel OverlayDetector::assessThreat(const OverlayAppInfo &app) {
  // Whitelist
  if (app.is_whitelisted || whitelist_.count(app.package_name) > 0) {
    return OverlayThreatLevel::SAFE;
  }

  // Sistem uygulaması
  if (app.is_system_app) {
    return OverlayThreatLevel::SAFE;
  }

  // İzin var ama aktif çizim yok
  if (!app.is_currently_drawing) {
    return OverlayThreatLevel::LOW;
  }

  // Sık overlay açıyorsa şüpheli
  if (app.overlay_count > 10) {
    return OverlayThreatLevel::HIGH;
  }

  // Aktif çizim var
  return OverlayThreatLevel::MEDIUM;
}

void OverlayDetector::loadWhitelist() {
  // Varsayılan whitelist
  for (const auto &pkg : DEFAULT_WHITELIST) {
    whitelist_.insert(pkg);
  }

  // Kullanıcı whitelist'i (dosyadan)
  std::ifstream file("/data/clara/config/overlay_whitelist.txt");
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line[0] != '#') {
      whitelist_.insert(line);
    }
  }

  stats_.whitelisted_count = whitelist_.size();
}

void OverlayDetector::saveWhitelist() {
  std::ofstream file("/data/clara/config/overlay_whitelist.txt");
  for (const auto &pkg : whitelist_) {
    // Varsayılanları kaydetme
    if (std::find(DEFAULT_WHITELIST.begin(), DEFAULT_WHITELIST.end(), pkg) ==
        DEFAULT_WHITELIST.end()) {
      file << pkg << "\n";
    }
  }
}

void OverlayDetector::loadSensitiveApps() {
  sensitive_apps_ = SENSITIVE_APPS;
  syslog(LOG_INFO, "%zu hassas uygulama tanımlı", sensitive_apps_.size());
}

} // namespace clara
