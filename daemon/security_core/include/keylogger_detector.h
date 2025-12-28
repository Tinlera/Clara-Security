/**
 * CLARA Security - Keylogger Detector
 * Accessibility servisini kötüye kullanan uygulamaları tespit eder
 */

#ifndef CLARA_KEYLOGGER_DETECTOR_H
#define CLARA_KEYLOGGER_DETECTOR_H

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace clara {

// Tehdit seviyesi
enum class KeyloggerRisk {
  NONE = 0,
  LOW = 1,     // Accessibility var ama meşru kullanım
  MEDIUM = 2,  // Şüpheli izin kombinasyonu
  HIGH = 3,    // Yüksek olasılıklı keylogger
  CRITICAL = 4 // Kesin keylogger/spyware
};

// Şüpheli uygulama bilgisi
struct SuspiciousApp {
  std::string package_name;
  std::string app_name;
  KeyloggerRisk risk_level;
  std::vector<std::string> suspicious_permissions;
  std::vector<std::string> suspicious_behaviors;
  std::string recommendation;
  bool is_accessibility_enabled;
  bool is_device_admin;
  bool has_overlay_permission;
};

/**
 * Keylogger Detector
 * - Accessibility servislerini listeler
 * - Tehlikeli izin kombinasyonlarını tespit eder
 * - Overlay + Accessibility = Banking Trojan şüphesi
 * - Device Admin + SMS = Ransomware şüphesi
 */
class KeyloggerDetector {
public:
  KeyloggerDetector();
  ~KeyloggerDetector();

  // Lifecycle
  bool initialize();
  void start();
  void stop();
  bool isRunning() const { return running_.load(); }

  // Tarama
  std::vector<SuspiciousApp> scanForKeyloggers();
  SuspiciousApp analyzeApp(const std::string &package_name);

  // Accessibility servisleri
  std::vector<std::string> getEnabledAccessibilityServices();
  std::vector<std::string> getDeviceAdmins();
  std::vector<std::string> getOverlayApps();

  // Whitelist yönetimi
  void addToWhitelist(const std::string &package_name);
  void removeFromWhitelist(const std::string &package_name);
  bool isWhitelisted(const std::string &package_name);

  // Callback
  using ThreatCallback = std::function<void(const SuspiciousApp &)>;
  void setThreatCallback(ThreatCallback callback) { callback_ = callback; }

  // İstatistikler
  int getSuspiciousAppCount() const { return suspicious_apps_.size(); }

private:
  void monitorLoop();

  // Android sistem sorguları
  std::string runShellCommand(const std::string &cmd);
  std::vector<std::string> parsePackageList(const std::string &output);
  std::vector<std::string> getAppPermissions(const std::string &package);

  // Risk hesaplama
  KeyloggerRisk calculateRisk(const std::string &package,
                              bool has_accessibility, bool is_admin,
                              bool has_overlay,
                              const std::vector<std::string> &permissions);

  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  ThreatCallback callback_;

  // Tespit edilen şüpheli uygulamalar
  std::vector<SuspiciousApp> suspicious_apps_;

  // Whitelist (güvenilir accessibility uygulamaları)
  std::unordered_set<std::string> whitelist_ = {
      "com.google.android.marvin.talkback", // TalkBack
      "com.samsung.accessibility", "com.miui.accessibility",
      "com.android.systemui"};

  // Tehlikeli izin kombinasyonları
  std::vector<std::vector<std::string>> dangerous_combos_ = {
      {"BIND_ACCESSIBILITY_SERVICE", "INTERNET", "READ_SMS"},
      {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"},
      {"BIND_DEVICE_ADMIN", "SEND_SMS", "INTERNET"},
      {"BIND_ACCESSIBILITY_SERVICE", "RECORD_AUDIO"},
      {"BIND_ACCESSIBILITY_SERVICE", "READ_CONTACTS", "INTERNET"}};

  int check_interval_ms_ = 60000; // Her dakika kontrol
};

} // namespace clara

#endif // CLARA_KEYLOGGER_DETECTOR_H
