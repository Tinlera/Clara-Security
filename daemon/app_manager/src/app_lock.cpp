/**
 * CLARA Security - App Lock Implementation
 * Uygulama kilitleme sistemi
 */

#include "../include/app_lock.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <regex>
#include <sstream>
#include <syslog.h>

// Koşullu OpenSSL include
#ifndef ANDROID_NO_EXTERNAL_LIBS
#include <openssl/sha.h>
#define HAS_OPENSSL 1
#else
#define HAS_OPENSSL 0
#endif

namespace clara {

AppLock::AppLock() { syslog(LOG_INFO, "App Lock oluşturuluyor..."); }

AppLock::~AppLock() {
  stop();
  saveConfig();
}

bool AppLock::initialize() {
  syslog(LOG_INFO, "App Lock başlatılıyor...");

  loadConfig();

  return true;
}

void AppLock::start() {
  if (running_.load())
    return;

  running_ = true;
  monitor_thread_ = std::thread(&AppLock::monitorLoop, this);

  syslog(LOG_INFO, "App Lock başlatıldı - %zu uygulama kilitli",
         locked_packages_.size());
}

void AppLock::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  saveConfig();

  syslog(LOG_INFO, "App Lock durduruldu");
}

void AppLock::monitorLoop() {
  std::string last_foreground;

  while (running_.load()) {
    try {
      std::string current = getCurrentForegroundApp();

      if (current != last_foreground) {
        // Yeni uygulama açıldı
        if (isAppLocked(current)) {
          // Geçici olarak açık mı?
          if (temp_unlocked_.count(current) > 0) {
            auto now = static_cast<uint64_t>(
                std::chrono::system_clock::now().time_since_epoch().count());
            if (now < temp_unlocked_[current]) {
              // Hala açık
              last_foreground = current;
              continue;
            } else {
              // Süre doldu, kaldır
              temp_unlocked_.erase(current);
            }
          }

          // Kilit ekranı göster
          if (launch_callback_) {
            launch_callback_(current);
          }

          if (lock_callback_) {
            lock_callback_(current, true);
          }

          // Log
          LockEvent event;
          event.package_name = current;
          event.timestamp =
              std::chrono::system_clock::now().time_since_epoch().count();
          event.is_unlock = false;
          event.is_successful = false;
          event.method_used = lock_types_[current];
          lock_history_.push_back(event);
        }

        last_foreground = current;
      }

    } catch (const std::exception &e) {
      syslog(LOG_ERR, "App Lock hata: %s", e.what());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

std::string AppLock::getCurrentForegroundApp() {
  // dumpsys activity ile ön plandaki uygulamayı bul
  std::array<char, 4096> buffer;
  std::string result;

  FILE *pipe = popen(
      "dumpsys activity activities | grep mResumedActivity | head -1", "r");

  if (pipe) {
    if (fgets(buffer.data(), buffer.size(), pipe)) {
      result = buffer.data();
    }
    pclose(pipe);
  }

  // Parse: "mResumedActivity: ActivityRecord{xxx com.example.app/.Activity"
  size_t start = result.find("com.");
  if (start == std::string::npos) {
    start = result.find("org.");
  }
  if (start == std::string::npos) {
    start = result.find("net.");
  }

  if (start != std::string::npos) {
    size_t end = result.find('/', start);
    if (end != std::string::npos) {
      return result.substr(start, end - start);
    }
  }

  return "";
}

void AppLock::lockApp(const std::string &package_name) {
  locked_packages_.insert(package_name);
  lock_types_[package_name] = LockType::PIN; // Varsayılan

  AppLockStatus status;
  status.package_name = package_name;
  status.app_name = package_name;
  status.is_locked = true;
  status.lock_type = LockType::PIN;
  status.failed_attempts = 0;
  status.is_temporarily_unlocked = false;

  lock_status_[package_name] = status;

  saveConfig();

  syslog(LOG_INFO, "Uygulama kilitlendi: %s", package_name.c_str());
}

void AppLock::unlockApp(const std::string &package_name) {
  locked_packages_.erase(package_name);
  lock_types_.erase(package_name);
  lock_status_.erase(package_name);

  saveConfig();

  syslog(LOG_INFO, "Uygulama kilidi kaldırıldı: %s", package_name.c_str());
}

bool AppLock::isAppLocked(const std::string &package_name) {
  return locked_packages_.count(package_name) > 0;
}

void AppLock::setLockType(const std::string &package_name, LockType type) {
  lock_types_[package_name] = type;

  if (lock_status_.count(package_name) > 0) {
    lock_status_[package_name].lock_type = type;
  }

  saveConfig();
}

LockType AppLock::getLockType(const std::string &package_name) {
  if (lock_types_.count(package_name) > 0) {
    return lock_types_[package_name];
  }
  return LockType::NONE;
}

std::string AppLock::hashPin(const std::string &pin) {
#if HAS_OPENSSL
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256((const unsigned char *)pin.c_str(), pin.length(), hash);

  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }

  return ss.str();
#else
  // Android fallback: echo+sha256sum kullan
  std::string cmd = "echo -n '" + pin + "' | sha256sum | cut -d' ' -f1";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    return "";

  char buffer[128];
  std::string result;
  if (fgets(buffer, sizeof(buffer), pipe)) {
    result = buffer;
    if (!result.empty() && result.back() == '\n') {
      result.pop_back();
    }
  }
  pclose(pipe);
  return result;
#endif
}

bool AppLock::setMasterPin(const std::string &pin) {
  if (pin.length() < 4) {
    syslog(LOG_WARNING, "PIN çok kısa (minimum 4 karakter)");
    return false;
  }

  master_pin_hash_ = hashPin(pin);
  saveConfig();

  syslog(LOG_INFO, "Master PIN ayarlandı");
  return true;
}

bool AppLock::verifyPin(const std::string &pin) {
  return hashPin(pin) == master_pin_hash_;
}

bool AppLock::setMasterPattern(const std::vector<int> &pattern) {
  if (pattern.size() < 4) {
    syslog(LOG_WARNING, "Pattern çok kısa (minimum 4 nokta)");
    return false;
  }

  // Pattern'i string'e çevir ve hashle
  std::stringstream ss;
  for (int p : pattern) {
    ss << p;
  }

  master_pattern_hash_ = hashPin(ss.str());
  saveConfig();

  syslog(LOG_INFO, "Master pattern ayarlandı");
  return true;
}

bool AppLock::verifyPattern(const std::vector<int> &pattern) {
  std::stringstream ss;
  for (int p : pattern) {
    ss << p;
  }

  return hashPin(ss.str()) == master_pattern_hash_;
}

bool AppLock::isBiometricAvailable() {
  // Biyometrik donanım kontrolü
  FILE *pipe = popen("getprop ro.hardware.fingerprint", "r");
  if (pipe) {
    char buffer[128];
    bool available =
        fgets(buffer, sizeof(buffer), pipe) != nullptr && strlen(buffer) > 1;
    pclose(pipe);
    return available;
  }
  return false;
}

void AppLock::enableBiometric(bool enable) {
  biometric_enabled_ = enable;
  saveConfig();

  syslog(LOG_INFO, "Biyometrik: %s", enable ? "aktif" : "pasif");
}

std::vector<AppLockStatus> AppLock::getLockedApps() {
  std::vector<AppLockStatus> apps;

  for (const auto &pair : lock_status_) {
    apps.push_back(pair.second);
  }

  return apps;
}

std::vector<std::string> AppLock::getLockedPackages() {
  return std::vector<std::string>(locked_packages_.begin(),
                                  locked_packages_.end());
}

void AppLock::temporaryUnlock(const std::string &package_name, int seconds) {
  auto until = std::chrono::system_clock::now().time_since_epoch().count() +
               (seconds * 1000000000LL);

  temp_unlocked_[package_name] = until;

  if (lock_status_.count(package_name) > 0) {
    lock_status_[package_name].is_temporarily_unlocked = true;
  }

  // Log
  LockEvent event;
  event.package_name = package_name;
  event.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
  event.is_unlock = true;
  event.is_successful = true;
  lock_history_.push_back(event);

  syslog(LOG_INFO, "Geçici kilit açma: %s (%d saniye)", package_name.c_str(),
         seconds);
}

void AppLock::relockApp(const std::string &package_name) {
  temp_unlocked_.erase(package_name);

  if (lock_status_.count(package_name) > 0) {
    lock_status_[package_name].is_temporarily_unlocked = false;
  }

  syslog(LOG_INFO, "Uygulama tekrar kilitlendi: %s", package_name.c_str());
}

std::vector<LockEvent> AppLock::getLockHistory(int count) {
  std::vector<LockEvent> result;

  int start = std::max(0, static_cast<int>(lock_history_.size()) - count);
  for (size_t i = start; i < lock_history_.size(); i++) {
    result.push_back(lock_history_[i]);
  }

  return result;
}

void AppLock::saveConfig() {
  std::ofstream file(config_path_);
  if (!file.is_open()) {
    syslog(LOG_ERR, "Config dosyası yazılamadı: %s", config_path_.c_str());
    return;
  }

  // JSON formatında kaydet
  file << "{\n";
  file << "  \"master_pin_hash\": \"" << master_pin_hash_ << "\",\n";
  file << "  \"master_pattern_hash\": \"" << master_pattern_hash_ << "\",\n";
  file << "  \"biometric_enabled\": " << (biometric_enabled_ ? "true" : "false")
       << ",\n";

  file << "  \"locked_packages\": [\n";
  bool first = true;
  for (const auto &pkg : locked_packages_) {
    if (!first)
      file << ",\n";
    file << "    \"" << pkg << "\"";
    first = false;
  }
  file << "\n  ]\n";

  file << "}\n";

  file.close();
}

void AppLock::loadConfig() {
  std::ifstream file(config_path_);
  if (!file.is_open()) {
    syslog(LOG_INFO, "Config dosyası bulunamadı, varsayılanlar kullanılıyor");
    return;
  }

  // Basit JSON parse
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  // master_pin_hash
  size_t pos = content.find("\"master_pin_hash\":");
  if (pos != std::string::npos) {
    size_t start = content.find("\"", pos + 17) + 1;
    size_t end = content.find("\"", start);
    master_pin_hash_ = content.substr(start, end - start);
  }

  // master_pattern_hash
  pos = content.find("\"master_pattern_hash\":");
  if (pos != std::string::npos) {
    size_t start = content.find("\"", pos + 21) + 1;
    size_t end = content.find("\"", start);
    master_pattern_hash_ = content.substr(start, end - start);
  }

  // biometric_enabled
  biometric_enabled_ =
      content.find("\"biometric_enabled\": true") != std::string::npos;

  // locked_packages
  std::regex pkg_regex("\"([a-zA-Z0-9_.]+)\"");
  pos = content.find("\"locked_packages\":");
  if (pos != std::string::npos) {
    size_t end = content.find("]", pos);
    std::string packages_str = content.substr(pos, end - pos);

    std::sregex_iterator it(packages_str.begin(), packages_str.end(),
                            pkg_regex);
    std::sregex_iterator end_it;

    // İlk eşleşmeyi atla (locked_packages kendisi)
    if (it != end_it)
      ++it;

    while (it != end_it) {
      std::string pkg = (*it)[1].str();
      locked_packages_.insert(pkg);
      lock_types_[pkg] = LockType::PIN;
      ++it;
    }
  }

  syslog(LOG_INFO, "Config yüklendi: %zu kilitli uygulama",
         locked_packages_.size());
}

void AppLock::showLockOverlay(const std::string &package) {
  // Android overlay göster (am komutu ile)
  std::string cmd = "am start -n com.clara.security/.LockActivity --es "
                    "package \"" +
                    package + "\"";
  system(cmd.c_str());
}

void AppLock::hideLockOverlay() {
  // Overlay'i kapat
  system("am broadcast -a com.clara.security.HIDE_LOCK");
}

} // namespace clara
