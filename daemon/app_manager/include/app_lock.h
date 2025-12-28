/**
 * CLARA Security - App Lock
 * Uygulamaları PIN veya biyometrik ile korur
 */

#ifndef CLARA_APP_LOCK_H
#define CLARA_APP_LOCK_H

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clara {

// Kilit türü
enum class LockType { NONE, PIN, PATTERN, FINGERPRINT, FACE };

// Kilit durumu
struct AppLockStatus {
  std::string package_name;
  std::string app_name;
  bool is_locked;
  LockType lock_type;
  uint64_t last_unlock_time;
  int failed_attempts;
  bool is_temporarily_unlocked; // Geçici olarak açık
};

// Kilit olayı
struct LockEvent {
  std::string package_name;
  uint64_t timestamp;
  bool is_unlock; // true = unlock, false = lock attempt
  bool is_successful;
  LockType method_used;
  std::string extra_info;
};

/**
 * App Lock Manager
 * - Uygulama başlatmalarını izler
 * - Kilitli uygulamalar için overlay gösterir
 * - Biyometrik doğrulama koordine eder
 */
class AppLock {
public:
  AppLock();
  ~AppLock();

  // Lifecycle
  bool initialize();
  void start();
  void stop();
  bool isRunning() const { return running_.load(); }

  // Uygulama kilitleme
  void lockApp(const std::string &package_name);
  void unlockApp(const std::string &package_name);
  bool isAppLocked(const std::string &package_name);

  // Kilit türü ayarlama
  void setLockType(const std::string &package_name, LockType type);
  LockType getLockType(const std::string &package_name);

  // Master PIN/Pattern
  bool setMasterPin(const std::string &pin);
  bool verifyPin(const std::string &pin);
  bool setMasterPattern(const std::vector<int> &pattern);
  bool verifyPattern(const std::vector<int> &pattern);

  // Biyometrik
  bool isBiometricAvailable();
  void enableBiometric(bool enable);

  // Kilitli uygulamalar listesi
  std::vector<AppLockStatus> getLockedApps();
  std::vector<std::string> getLockedPackages();

  // Geçici kilit açma
  void temporaryUnlock(const std::string &package_name, int seconds = 60);
  void relockApp(const std::string &package_name);

  // Olay geçmişi
  std::vector<LockEvent> getLockHistory(int count = 50);

  // Callbacks
  using LockCallback =
      std::function<void(const std::string &package, bool needs_unlock)>;
  void setLockCallback(LockCallback callback) { lock_callback_ = callback; }

  // Uygulama başlatma callback (overlay göstermek için)
  using AppLaunchCallback = std::function<void(const std::string &package)>;
  void setAppLaunchCallback(AppLaunchCallback callback) {
    launch_callback_ = callback;
  }

private:
  void monitorLoop();

  // Uygulama başlatma izleme
  void watchAppLaunches();
  std::string getCurrentForegroundApp();

  // Overlay kontrolü
  void showLockOverlay(const std::string &package);
  void hideLockOverlay();

  // PIN hash'leme
  std::string hashPin(const std::string &pin);

  // Kaydetme/yükleme
  void saveConfig();
  void loadConfig();

  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  LockCallback lock_callback_;
  AppLaunchCallback launch_callback_;

  // Kilitli uygulamalar
  std::unordered_set<std::string> locked_packages_;
  std::unordered_map<std::string, LockType> lock_types_;
  std::unordered_map<std::string, AppLockStatus> lock_status_;

  // Geçici olarak açık uygulamalar
  std::unordered_map<std::string, uint64_t>
      temp_unlocked_; // package -> unlock_until_time

  // Master credentials (hashed)
  std::string master_pin_hash_;
  std::string master_pattern_hash_;
  bool biometric_enabled_ = true;

  // Olay geçmişi
  std::vector<LockEvent> lock_history_;

  // Ayarlar
  int max_failed_attempts_ = 5;
  int lockout_duration_seconds_ = 300; // 5 dakika
  std::string config_path_ = "/data/clara/applock.json";
};

} // namespace clara

#endif // CLARA_APP_LOCK_H
