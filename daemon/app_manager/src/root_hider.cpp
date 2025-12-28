/**
 * CLARA Security - Root Hider Implementation
 * Root tespitinden gizleme
 */

#include "../include/root_hider.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <syslog.h>

namespace clara {

RootHider::RootHider() { syslog(LOG_INFO, "Root Hider oluşturuluyor..."); }

RootHider::~RootHider() { stop(); }

bool RootHider::initialize() {
  syslog(LOG_INFO, "Root Hider başlatılıyor...");

  // KernelSU kontrolü
  if (!isKernelSuAvailable()) {
    syslog(LOG_WARNING, "KernelSU bulunamadı");
  }

  // Config yükle
  std::ifstream file(config_path_);
  if (file.is_open()) {
    // TODO: JSON parse ve hidden_packages_ yükle
    file.close();
  }

  return true;
}

void RootHider::start() {
  if (running_.load())
    return;

  running_ = true;

  // Otomatik banka uygulamaları tespiti
  autoHideBankApps();

  monitor_thread_ = std::thread(&RootHider::monitorLoop, this);

  syslog(LOG_INFO, "Root Hider başlatıldı - %zu uygulama gizlendi",
         hidden_packages_.size());
}

void RootHider::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  // Config kaydet
  std::ofstream file(config_path_);
  if (file.is_open()) {
    file << "{\n  \"hidden_packages\": [\n";
    bool first = true;
    for (const auto &pkg : hidden_packages_) {
      if (!first)
        file << ",\n";
      file << "    \"" << pkg << "\"";
      first = false;
    }
    file << "\n  ]\n}\n";
    file.close();
  }

  syslog(LOG_INFO, "Root Hider durduruldu");
}

void RootHider::monitorLoop() {
  while (running_.load()) {
    try {
      // Periyodik olarak yeni banka uygulamalarını kontrol et
      auto bank_apps = detectBankApps();

      for (const auto &app : bank_apps) {
        if (hidden_packages_.count(app) == 0) {
          hideFromApp(app);
        }
      }

    } catch (const std::exception &e) {
      syslog(LOG_ERR, "Root Hider hata: %s", e.what());
    }

    std::this_thread::sleep_for(std::chrono::seconds(60));
  }
}

bool RootHider::isKernelSuAvailable() {
  // KernelSU binary kontrolü
  struct stat st;
  return stat("/data/adb/ksud", &st) == 0 || stat("/data/adb/ksu", &st) == 0;
}

std::string RootHider::runKsuCommand(const std::string &cmd) {
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

void RootHider::hideFromApp(const std::string &package_name) {
  if (!isAppInstalled(package_name)) {
    syslog(LOG_WARNING, "Uygulama yüklü değil: %s", package_name.c_str());
    return;
  }

  hidden_packages_.insert(package_name);
  hide_levels_[package_name] = HideStatus::HIDDEN_ADVANCED;

  // KernelSU denylist'e ekle
  if (isKernelSuAvailable()) {
    addToKsuDenylist(package_name);
  }

  // Prop gizleme
  hideRootProps();

  syslog(LOG_INFO, "Root gizlendi: %s", package_name.c_str());
}

void RootHider::unhideFromApp(const std::string &package_name) {
  hidden_packages_.erase(package_name);
  hide_levels_.erase(package_name);

  // KernelSU denylist'ten çıkar
  if (isKernelSuAvailable()) {
    removeFromKsuDenylist(package_name);
  }

  syslog(LOG_INFO, "Root gizleme kaldırıldı: %s", package_name.c_str());
}

bool RootHider::isHiddenFrom(const std::string &package_name) {
  return hidden_packages_.count(package_name) > 0;
}

HideStatus RootHider::getHideStatus(const std::string &package_name) {
  if (hide_levels_.count(package_name) > 0) {
    return hide_levels_[package_name];
  }
  return HideStatus::NOT_HIDDEN;
}

void RootHider::setHideLevel(const std::string &package_name,
                             HideStatus level) {
  hide_levels_[package_name] = level;
  syslog(LOG_INFO, "Gizleme seviyesi ayarlandı: %s = %d", package_name.c_str(),
         static_cast<int>(level));
}

std::vector<std::string> RootHider::detectBankApps() {
  std::vector<std::string> found_apps;

  // Yüklü uygulamaları listele
  std::string output = runKsuCommand("pm list packages");

  for (const auto &known_bank : known_bank_apps_) {
    if (output.find(known_bank) != std::string::npos) {
      found_apps.push_back(known_bank);
    }
  }

  return found_apps;
}

void RootHider::autoHideBankApps() {
  auto bank_apps = detectBankApps();

  for (const auto &app : bank_apps) {
    if (hidden_packages_.count(app) == 0) {
      hideFromApp(app);
      syslog(LOG_INFO, "Banka uygulaması otomatik gizlendi: %s", app.c_str());
    }
  }
}

std::vector<RootDetectionInfo> RootHider::scanForRootDetectors() {
  std::vector<RootDetectionInfo> detectors;

  // Bilinen root detector uygulamalarını kontrol et
  for (const auto &detector : known_detectors_) {
    if (isAppInstalled(detector)) {
      RootDetectionInfo info;
      info.package_name = detector;
      info.app_name = detector;
      info.detects_root = true;
      info.detects_magisk = true;
      info.uses_safetynet = false;
      info.is_bank_app = false;
      info.hide_status = getHideStatus(detector);

      detectors.push_back(info);
    }
  }

  // Banka uygulamalarını da ekle
  for (const auto &bank : known_bank_apps_) {
    if (isAppInstalled(bank)) {
      RootDetectionInfo info;
      info.package_name = bank;
      info.app_name = bank;
      info.detects_root = true;
      info.detects_magisk = true;
      info.uses_safetynet = true;
      info.is_bank_app = true;
      info.hide_status = getHideStatus(bank);

      detectors.push_back(info);
    }
  }

  return detectors;
}

bool RootHider::doesAppDetectRoot(const std::string &package_name) {
  return known_bank_apps_.count(package_name) > 0 ||
         known_detectors_.count(package_name) > 0;
}

bool RootHider::addToKsuDenylist(const std::string &package_name) {
  // KernelSU denylist'e ekle
  std::string cmd = "ksud module deny " + package_name;
  std::string result = runKsuCommand(cmd);

  return result.find("success") != std::string::npos ||
         result.find("already") != std::string::npos;
}

bool RootHider::removeFromKsuDenylist(const std::string &package_name) {
  std::string cmd = "ksud module allow " + package_name;
  std::string result = runKsuCommand(cmd);

  return result.find("success") != std::string::npos;
}

std::vector<std::string> RootHider::getKsuDenylist() {
  std::vector<std::string> list;

  std::string output = runKsuCommand("ksud module list --denied");

  std::istringstream stream(output);
  std::string line;

  while (std::getline(stream, line)) {
    if (!line.empty()) {
      list.push_back(line);
    }
  }

  return list;
}

void RootHider::hideRootProps() {
  for (const auto &prop : root_props_) {
    setProp(prop.first, prop.second);
  }

  syslog(LOG_INFO, "Root prop'ları gizlendi");
}

void RootHider::restoreRootProps() {
  for (const auto &prop : root_props_) {
    resetProp(prop.first);
  }

  syslog(LOG_INFO, "Root prop'ları geri yüklendi");
}

std::string RootHider::getOriginalProp(const std::string &prop_name) {
  std::string cmd = "getprop " + prop_name;
  return runKsuCommand(cmd);
}

void RootHider::setProp(const std::string &prop_name,
                        const std::string &value) {
  // resetprop kullan (Magisk/KernelSU)
  std::string cmd = "resetprop " + prop_name + " " + value;
  system(cmd.c_str());
}

void RootHider::resetProp(const std::string &prop_name) {
  std::string cmd = "resetprop --delete " + prop_name;
  system(cmd.c_str());
}

void RootHider::hideSuBinary() {
  // Su binary'lerini geçici olarak yeniden adlandır
  system("mv /system/bin/su /system/bin/.su_hidden 2>/dev/null");
  system("mv /system/xbin/su /system/xbin/.su_hidden 2>/dev/null");

  syslog(LOG_INFO, "Su binary gizlendi");
}

void RootHider::restoreSuBinary() {
  system("mv /system/bin/.su_hidden /system/bin/su 2>/dev/null");
  system("mv /system/xbin/.su_hidden /system/xbin/su 2>/dev/null");

  syslog(LOG_INFO, "Su binary geri yüklendi");
}

std::vector<std::string> RootHider::getHiddenPackages() {
  return std::vector<std::string>(hidden_packages_.begin(),
                                  hidden_packages_.end());
}

std::vector<RootDetectionInfo> RootHider::getAllAppsInfo() {
  std::vector<RootDetectionInfo> all_apps;

  for (const auto &pair : app_info_) {
    all_apps.push_back(pair.second);
  }

  return all_apps;
}

bool RootHider::isAppInstalled(const std::string &package_name) {
  std::string cmd = "pm path " + package_name;
  std::string output = runKsuCommand(cmd);

  return output.find("package:") != std::string::npos;
}

std::string RootHider::getAppPath(const std::string &package_name) {
  std::string cmd = "pm path " + package_name;
  std::string output = runKsuCommand(cmd);

  // "package:/data/app/..." formatından path'i çıkar
  size_t start = output.find("package:");
  if (start != std::string::npos) {
    start += 8;
    size_t end = output.find('\n', start);
    return output.substr(start, end - start);
  }

  return "";
}

bool RootHider::setupMountNamespace(const std::string &package_name) {
  // Mount namespace ile izolasyon
  // Bu karmaşık bir işlem, Zygisk ile daha kolay yapılabilir
  syslog(LOG_INFO, "Mount namespace kurulumu: %s", package_name.c_str());
  return true;
}

std::vector<std::string>
RootHider::analyzeDetectionMethods(const std::string &package_name) {
  std::vector<std::string> methods;

  std::string apk_path = getAppPath(package_name);
  if (apk_path.empty()) {
    return methods;
  }

  // APK içinde bilinen root detection string'lerini ara
  std::string cmd = "unzip -p " + apk_path +
                    " classes.dex 2>/dev/null | strings | grep -iE "
                    "'su|root|magisk|superuser'";
  std::string output = runKsuCommand(cmd);

  if (output.find("su") != std::string::npos) {
    methods.push_back("su_binary_check");
  }
  if (output.find("Superuser") != std::string::npos) {
    methods.push_back("superuser_apk_check");
  }
  if (output.find("magisk") != std::string::npos ||
      output.find("Magisk") != std::string::npos) {
    methods.push_back("magisk_check");
  }
  if (output.find("safetynet") != std::string::npos ||
      output.find("SafetyNet") != std::string::npos) {
    methods.push_back("safetynet_attestation");
  }
  if (output.find("RootBeer") != std::string::npos) {
    methods.push_back("rootbeer_library");
  }

  return methods;
}

bool RootHider::testHiding(const std::string &package_name) {
  // Gizlemenin çalışıp çalışmadığını test et
  if (!isHiddenFrom(package_name)) {
    return false;
  }

  // KernelSU denylist kontrolü
  auto denylist = getKsuDenylist();
  bool in_denylist = std::find(denylist.begin(), denylist.end(),
                               package_name) != denylist.end();

  if (!in_denylist) {
    syslog(LOG_WARNING, "Uygulama KernelSU denylist'te değil: %s",
           package_name.c_str());
  }

  return in_denylist;
}

} // namespace clara
