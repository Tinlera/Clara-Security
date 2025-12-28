/**
 * CLARA Security - Permission Watcher Implementation
 * İzin kullanımlarını izler ve raporlar
 */

#include "../include/permission_watcher.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <syslog.h>

namespace clara {

PermissionWatcher::PermissionWatcher() {
  syslog(LOG_INFO, "Permission Watcher oluşturuluyor...");
}

PermissionWatcher::~PermissionWatcher() { stop(); }

bool PermissionWatcher::initialize() {
  syslog(LOG_INFO, "Permission Watcher başlatılıyor...");
  return true;
}

void PermissionWatcher::start() {
  if (running_.load())
    return;

  running_ = true;
  monitor_thread_ = std::thread(&PermissionWatcher::monitorLoop, this);
  logcat_thread_ = std::thread(&PermissionWatcher::watchLogcat, this);

  syslog(LOG_INFO, "Permission Watcher başlatıldı");
}

void PermissionWatcher::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  if (logcat_thread_.joinable()) {
    logcat_thread_.join();
  }

  syslog(LOG_INFO, "Permission Watcher durduruldu");
}

void PermissionWatcher::monitorLoop() {
  while (running_.load()) {
    try {
      // AppOps sorgusu
      auto usages = queryAppOps();

      for (const auto &usage : usages) {
        // Geçmişe ekle
        usage_history_.push_back(usage);

        // Boyut kontrolü
        if (usage_history_.size() > max_history_size_) {
          usage_history_.erase(usage_history_.begin());
        }

        // İstatistikleri güncelle
        auto &stats = app_stats_[usage.package_name];
        stats.package_name = usage.package_name;
        stats.app_name = usage.app_name;
        stats.usage_counts[usage.permission_type]++;
        stats.total_duration_ms[usage.permission_type] += usage.duration_ms;
        stats.last_access_time = usage.timestamp;

        if (!usage.is_foreground) {
          stats.background_access_count++;
        }

        // Callback
        if (callback_) {
          callback_(usage);
        }

        // Alert threshold kontrolü
        if (alert_thresholds_.count(usage.permission_type) > 0) {
          int count = stats.usage_counts[usage.permission_type];
          if (count > alert_thresholds_[usage.permission_type]) {
            syslog(LOG_WARNING, "İzin kullanım uyarısı: %s - %s (%d kez)",
                   usage.package_name.c_str(), usage.permission_name.c_str(),
                   count);
          }
        }
      }

    } catch (const std::exception &e) {
      syslog(LOG_ERR, "Permission Watcher hata: %s", e.what());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(check_interval_ms_));
  }
}

std::string PermissionWatcher::runAppOpsCommand(const std::string &cmd) {
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

std::vector<PermissionUsage> PermissionWatcher::queryAppOps() {
  std::vector<PermissionUsage> usages;

  // AppOps log'larını sorgula
  std::string output = runAppOpsCommand("dumpsys appops --short");

  std::istringstream stream(output);
  std::string line;
  std::string current_package;

  while (std::getline(stream, line)) {
    // Paket satırı
    if (line.find("Package ") == 0) {
      size_t start = line.find("Package ") + 8;
      size_t end = line.find(':', start);
      current_package = line.substr(start, end - start);
      continue;
    }

    // İzin kullanım satırı
    // Örnek: "CAMERA (allow); time=+1h2m3s ago; duration=+5s"
    if (line.find("time=") != std::string::npos && !current_package.empty()) {
      PermissionUsage usage;
      usage.package_name = current_package;
      usage.app_name = getAppName(current_package);
      usage.timestamp =
          std::chrono::system_clock::now().time_since_epoch().count();

      // İzin adını çıkar
      size_t perm_end = line.find(' ');
      if (perm_end != std::string::npos) {
        std::string perm_name = line.substr(0, perm_end);
        // Baştaki boşlukları temizle
        perm_name.erase(0, perm_name.find_first_not_of(" \t"));
        usage.permission_name = perm_name;
        usage.permission_type = classifyPermission(perm_name);
      }

      // Foreground/background
      usage.is_foreground = line.find("foreground") != std::string::npos;

      // Duration
      size_t dur_pos = line.find("duration=");
      if (dur_pos != std::string::npos) {
        // Basit parse - gerçek implementasyonda daha detaylı olmalı
        usage.duration_ms = 1000; // Placeholder
      }

      usages.push_back(usage);
    }
  }

  return usages;
}

void PermissionWatcher::watchLogcat() {
  // Logcat'ten izin erişimlerini izle
  FILE *pipe = popen("logcat -s PermissionController:* AppOps:* -v time", "r");

  if (!pipe) {
    syslog(LOG_ERR, "Logcat başlatılamadı");
    return;
  }

  std::array<char, 1024> buffer;

  while (running_.load() && fgets(buffer.data(), buffer.size(), pipe)) {
    std::string line(buffer.data());

    auto usage = parseLogcatLine(line);
    if (!usage.package_name.empty()) {
      usage_history_.push_back(usage);

      if (callback_) {
        callback_(usage);
      }
    }
  }

  pclose(pipe);
}

PermissionUsage PermissionWatcher::parseLogcatLine(const std::string &line) {
  PermissionUsage usage;

  // Örnek logcat satırı:
  // "I/AppOps : Permission ACCESS_FINE_LOCATION granted to com.example.app"

  if (line.find("Permission") != std::string::npos) {
    // İzin adını bul
    size_t perm_start = line.find("Permission ") + 11;
    size_t perm_end = line.find(' ', perm_start);
    if (perm_end != std::string::npos) {
      usage.permission_name = line.substr(perm_start, perm_end - perm_start);
      usage.permission_type = classifyPermission(usage.permission_name);
    }

    // Paket adını bul
    size_t pkg_start = line.find("to ");
    if (pkg_start != std::string::npos) {
      pkg_start += 3;
      size_t pkg_end = line.find_first_of(" \n", pkg_start);
      usage.package_name = line.substr(pkg_start, pkg_end - pkg_start);
      usage.app_name = getAppName(usage.package_name);
    }

    usage.timestamp =
        std::chrono::system_clock::now().time_since_epoch().count();
    usage.is_foreground = true;
  }

  return usage;
}

PermissionType
PermissionWatcher::classifyPermission(const std::string &permission_name) {
  if (permission_name.find("CAMERA") != std::string::npos) {
    return PermissionType::CAMERA;
  } else if (permission_name.find("RECORD_AUDIO") != std::string::npos ||
             permission_name.find("MICROPHONE") != std::string::npos) {
    return PermissionType::MICROPHONE;
  } else if (permission_name.find("LOCATION") != std::string::npos) {
    return PermissionType::LOCATION;
  } else if (permission_name.find("CONTACTS") != std::string::npos) {
    return PermissionType::CONTACTS;
  } else if (permission_name.find("SMS") != std::string::npos) {
    return PermissionType::SMS;
  } else if (permission_name.find("PHONE") != std::string::npos ||
             permission_name.find("CALL") != std::string::npos) {
    return PermissionType::PHONE;
  } else if (permission_name.find("STORAGE") != std::string::npos) {
    return PermissionType::STORAGE;
  } else if (permission_name.find("CALENDAR") != std::string::npos) {
    return PermissionType::CALENDAR;
  } else if (permission_name.find("SENSOR") != std::string::npos ||
             permission_name.find("ACTIVITY") != std::string::npos) {
    return PermissionType::SENSORS;
  }

  return PermissionType::OTHER;
}

std::string PermissionWatcher::getAppName(const std::string &package_name) {
  // TODO: PackageManager'dan gerçek uygulama adını al
  // Şimdilik paket adını döndür
  return package_name;
}

std::vector<PermissionUsage> PermissionWatcher::getRecentUsage(int hours) {
  std::vector<PermissionUsage> recent;

  auto now = std::chrono::system_clock::now().time_since_epoch().count();
  uint64_t cutoff = now - (hours * 3600 * 1000000000ULL); // Nanosaniye

  for (const auto &usage : usage_history_) {
    if (usage.timestamp >= cutoff) {
      recent.push_back(usage);
    }
  }

  return recent;
}

std::vector<PermissionUsage>
PermissionWatcher::getUsageByApp(const std::string &package) {
  std::vector<PermissionUsage> result;

  for (const auto &usage : usage_history_) {
    if (usage.package_name == package) {
      result.push_back(usage);
    }
  }

  return result;
}

std::vector<PermissionUsage>
PermissionWatcher::getUsageByPermission(PermissionType type) {
  std::vector<PermissionUsage> result;

  for (const auto &usage : usage_history_) {
    if (usage.permission_type == type) {
      result.push_back(usage);
    }
  }

  return result;
}

std::vector<AppPermissionStats> PermissionWatcher::getAppStats() {
  std::vector<AppPermissionStats> stats;

  for (const auto &pair : app_stats_) {
    stats.push_back(pair.second);
  }

  return stats;
}

AppPermissionStats
PermissionWatcher::getStatsForApp(const std::string &package) {
  if (app_stats_.count(package) > 0) {
    return app_stats_[package];
  }
  return AppPermissionStats();
}

int PermissionWatcher::getTotalAccessCount(PermissionType type) {
  int total = 0;

  for (const auto &pair : app_stats_) {
    if (pair.second.usage_counts.count(type) > 0) {
      total += pair.second.usage_counts.at(type);
    }
  }

  return total;
}

std::vector<std::string> PermissionWatcher::getTopAccessors(PermissionType type,
                                                            int count) {
  std::vector<std::pair<std::string, int>> apps;

  for (const auto &pair : app_stats_) {
    if (pair.second.usage_counts.count(type) > 0) {
      apps.push_back({pair.first, pair.second.usage_counts.at(type)});
    }
  }

  // Sırala
  std::sort(apps.begin(), apps.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });

  std::vector<std::string> result;
  for (int i = 0; i < count && i < static_cast<int>(apps.size()); i++) {
    result.push_back(apps[i].first);
  }

  return result;
}

std::vector<PermissionUsage> PermissionWatcher::getBackgroundAccesses() {
  std::vector<PermissionUsage> result;

  for (const auto &usage : usage_history_) {
    if (!usage.is_foreground) {
      result.push_back(usage);
    }
  }

  return result;
}

void PermissionWatcher::setAlertThreshold(PermissionType type,
                                          int max_per_hour) {
  alert_thresholds_[type] = max_per_hour;
  syslog(LOG_INFO, "Alert threshold ayarlandı: %d = %d/saat",
         static_cast<int>(type), max_per_hour);
}

// /proc izleme fonksiyonları
bool PermissionWatcher::isCameraInUse() {
  // /proc/asound veya kamera HAL durumunu kontrol et
  std::ifstream file("/proc/asound/card0/pcm0c/sub0/status");
  if (file.is_open()) {
    std::string line;
    std::getline(file, line);
    return line.find("RUNNING") != std::string::npos;
  }
  return false;
}

bool PermissionWatcher::isMicrophoneInUse() {
  // Audio capture durumunu kontrol et
  std::ifstream file("/proc/asound/card0/pcm0c/sub0/status");
  if (file.is_open()) {
    std::string line;
    std::getline(file, line);
    return line.find("RUNNING") != std::string::npos;
  }
  return false;
}

std::vector<std::string> PermissionWatcher::getProcessesUsingCamera() {
  std::vector<std::string> processes;

  // lsof ile kamera cihazını kullanan processleri bul
  FILE *pipe = popen("lsof /dev/video* 2>/dev/null | awk '{print $1}'", "r");
  if (pipe) {
    std::array<char, 256> buffer;
    while (fgets(buffer.data(), buffer.size(), pipe)) {
      std::string proc(buffer.data());
      proc.erase(proc.find_last_not_of(" \n\r\t") + 1);
      if (!proc.empty() && proc != "COMMAND") {
        processes.push_back(proc);
      }
    }
    pclose(pipe);
  }

  return processes;
}

std::vector<std::string> PermissionWatcher::getProcessesUsingMicrophone() {
  std::vector<std::string> processes;

  // lsof ile audio cihazını kullanan processleri bul
  FILE *pipe = popen("lsof /dev/snd/* 2>/dev/null | awk '{print $1}'", "r");
  if (pipe) {
    std::array<char, 256> buffer;
    while (fgets(buffer.data(), buffer.size(), pipe)) {
      std::string proc(buffer.data());
      proc.erase(proc.find_last_not_of(" \n\r\t") + 1);
      if (!proc.empty() && proc != "COMMAND") {
        processes.push_back(proc);
      }
    }
    pclose(pipe);
  }

  return processes;
}

} // namespace clara
