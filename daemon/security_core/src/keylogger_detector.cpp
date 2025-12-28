/**
 * CLARA Security - Keylogger Detector Implementation
 * Accessibility kötüye kullanan uygulamaları tespit eder
 */

#include "../include/keylogger_detector.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <syslog.h>

namespace clara {

KeyloggerDetector::KeyloggerDetector() {
  syslog(LOG_INFO, "Keylogger Detector oluşturuluyor...");
}

KeyloggerDetector::~KeyloggerDetector() { stop(); }

bool KeyloggerDetector::initialize() {
  syslog(LOG_INFO, "Keylogger Detector başlatılıyor...");

  // İlk taramayı yap
  scanForKeyloggers();

  return true;
}

void KeyloggerDetector::start() {
  if (running_.load())
    return;

  running_ = true;
  monitor_thread_ = std::thread(&KeyloggerDetector::monitorLoop, this);
  syslog(LOG_INFO, "Keylogger Detector başlatıldı");
}

void KeyloggerDetector::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  syslog(LOG_INFO, "Keylogger Detector durduruldu");
}

void KeyloggerDetector::monitorLoop() {
  while (running_.load()) {
    try {
      // Periyodik tarama
      auto threats = scanForKeyloggers();

      for (const auto &app : threats) {
        if (app.risk_level >= KeyloggerRisk::HIGH) {
          if (callback_) {
            callback_(app);
          }
        }
      }

    } catch (const std::exception &e) {
      syslog(LOG_ERR, "Keylogger Detector hata: %s", e.what());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(check_interval_ms_));
  }
}

std::string KeyloggerDetector::runShellCommand(const std::string &cmd) {
  std::array<char, 4096> buffer;
  std::string result;

  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    return "";
  }

  while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
    result += buffer.data();
  }

  pclose(pipe);
  return result;
}

std::vector<std::string>
KeyloggerDetector::parsePackageList(const std::string &output) {
  std::vector<std::string> packages;
  std::istringstream stream(output);
  std::string line;

  while (std::getline(stream, line)) {
    // "package:com.example.app" formatından paketi çıkar
    if (line.find("package:") == 0) {
      packages.push_back(line.substr(8));
    } else if (!line.empty()) {
      // Sadece paket adı
      packages.push_back(line);
    }
  }

  return packages;
}

std::vector<std::string> KeyloggerDetector::getEnabledAccessibilityServices() {
  std::string output =
      runShellCommand("settings get secure enabled_accessibility_services");

  std::vector<std::string> services;

  // Format: "com.app1/Service1:com.app2/Service2"
  std::istringstream stream(output);
  std::string service;

  while (std::getline(stream, service, ':')) {
    if (!service.empty() && service != "null") {
      // Sadece paket adını al (service adından önce)
      size_t slash_pos = service.find('/');
      if (slash_pos != std::string::npos) {
        services.push_back(service.substr(0, slash_pos));
      } else {
        services.push_back(service);
      }
    }
  }

  return services;
}

std::vector<std::string> KeyloggerDetector::getDeviceAdmins() {
  std::string output = runShellCommand("dumpsys device_policy");

  std::vector<std::string> admins;
  std::istringstream stream(output);
  std::string line;

  while (std::getline(stream, line)) {
    // "Admin:" satırlarını bul
    if (line.find("Admin{") != std::string::npos) {
      // Package adını çıkar
      size_t start = line.find("Admin{") + 6;
      size_t end = line.find('/', start);
      if (end != std::string::npos) {
        admins.push_back(line.substr(start, end - start));
      }
    }
  }

  return admins;
}

std::vector<std::string> KeyloggerDetector::getOverlayApps() {
  std::string output = runShellCommand(
      "cmd appops query-op --permission android:system_alert_window allow");

  return parsePackageList(output);
}

std::vector<std::string>
KeyloggerDetector::getAppPermissions(const std::string &package) {
  std::string output =
      runShellCommand("dumpsys package " + package + " | grep permission");

  std::vector<std::string> permissions;
  std::istringstream stream(output);
  std::string line;

  while (std::getline(stream, line)) {
    // "android.permission.XXX" formatındaki izinleri çıkar
    size_t pos = line.find("android.permission.");
    if (pos != std::string::npos) {
      size_t end = line.find_first_of(":,} \n", pos);
      std::string perm = line.substr(pos, end - pos);
      permissions.push_back(perm);
    }
  }

  return permissions;
}

std::vector<SuspiciousApp> KeyloggerDetector::scanForKeyloggers() {
  suspicious_apps_.clear();

  // Accessibility servisleri al
  auto accessibility_apps = getEnabledAccessibilityServices();

  // Device admin'leri al
  auto device_admins = getDeviceAdmins();

  // Overlay izni olan uygulamalar
  auto overlay_apps = getOverlayApps();

  // Her accessibility uygulamasını analiz et
  for (const auto &package : accessibility_apps) {
    if (isWhitelisted(package)) {
      continue;
    }

    SuspiciousApp app = analyzeApp(package);
    app.is_accessibility_enabled = true;

    // Device admin mi?
    app.is_device_admin = std::find(device_admins.begin(), device_admins.end(),
                                    package) != device_admins.end();

    // Overlay izni var mı?
    app.has_overlay_permission =
        std::find(overlay_apps.begin(), overlay_apps.end(), package) !=
        overlay_apps.end();

    // Risk hesapla
    auto permissions = getAppPermissions(package);
    app.risk_level = calculateRisk(package, true, app.is_device_admin,
                                   app.has_overlay_permission, permissions);

    if (app.risk_level >= KeyloggerRisk::MEDIUM) {
      suspicious_apps_.push_back(app);

      syslog(LOG_WARNING, "Şüpheli uygulama tespit edildi: %s (risk: %d)",
             package.c_str(), static_cast<int>(app.risk_level));
    }
  }

  return suspicious_apps_;
}

SuspiciousApp KeyloggerDetector::analyzeApp(const std::string &package_name) {
  SuspiciousApp app;
  app.package_name = package_name;
  app.app_name = package_name; // TODO: Gerçek uygulama adını al

  // İzinleri al
  auto permissions = getAppPermissions(package_name);
  app.suspicious_permissions = permissions;

  // Tehlikeli izin kombinasyonlarını kontrol et
  for (const auto &combo : dangerous_combos_) {
    int match_count = 0;
    for (const auto &perm : combo) {
      for (const auto &app_perm : permissions) {
        if (app_perm.find(perm) != std::string::npos) {
          match_count++;
          break;
        }
      }
    }

    if (match_count == static_cast<int>(combo.size())) {
      app.suspicious_behaviors.push_back(
          "Tehlikeli izin kombinasyonu: " + combo[0] + " + " + combo[1]);
    }
  }

  return app;
}

KeyloggerRisk
KeyloggerDetector::calculateRisk([[maybe_unused]] const std::string &package,
                                 bool has_accessibility, bool is_admin,
                                 bool has_overlay,
                                 const std::vector<std::string> &permissions) {
  int risk_score = 0;

  // Accessibility + Overlay = Banking Trojan olasılığı yüksek
  if (has_accessibility && has_overlay) {
    risk_score += 50;
  }

  // Accessibility + Device Admin = Çok tehlikeli
  if (has_accessibility && is_admin) {
    risk_score += 40;
  }

  // Sadece Accessibility
  if (has_accessibility) {
    risk_score += 20;
  }

  // Tehlikeli izinler
  std::vector<std::string> dangerous = {"SEND_SMS", "READ_SMS",
                                        "INTERNET", "READ_CONTACTS",
                                        "CAMERA",   "RECORD_AUDIO"};

  for (const auto &perm : permissions) {
    for (const auto &d : dangerous) {
      if (perm.find(d) != std::string::npos) {
        risk_score += 5;
      }
    }
  }

  // Risk seviyesini belirle
  if (risk_score >= 80) {
    return KeyloggerRisk::CRITICAL;
  } else if (risk_score >= 60) {
    return KeyloggerRisk::HIGH;
  } else if (risk_score >= 40) {
    return KeyloggerRisk::MEDIUM;
  } else if (risk_score >= 20) {
    return KeyloggerRisk::LOW;
  }

  return KeyloggerRisk::NONE;
}

void KeyloggerDetector::addToWhitelist(const std::string &package_name) {
  whitelist_.insert(package_name);
  syslog(LOG_INFO, "Whitelist'e eklendi: %s", package_name.c_str());
}

void KeyloggerDetector::removeFromWhitelist(const std::string &package_name) {
  whitelist_.erase(package_name);
  syslog(LOG_INFO, "Whitelist'ten çıkarıldı: %s", package_name.c_str());
}

bool KeyloggerDetector::isWhitelisted(const std::string &package_name) {
  return whitelist_.count(package_name) > 0;
}

} // namespace clara
