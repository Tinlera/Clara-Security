/**
 * CLARA Security - Permission Watcher
 * Uygulama izin kullanımlarını izler ve raporlar
 */

#ifndef CLARA_PERMISSION_WATCHER_H
#define CLARA_PERMISSION_WATCHER_H

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace clara {

// İzin türleri
enum class PermissionType {
  CAMERA,
  MICROPHONE,
  LOCATION,
  CONTACTS,
  SMS,
  PHONE,
  STORAGE,
  CALENDAR,
  SENSORS,
  OTHER
};

// İzin kullanım kaydı
struct PermissionUsage {
  std::string package_name;
  std::string app_name;
  PermissionType permission_type;
  std::string permission_name;
  uint64_t timestamp;
  uint64_t duration_ms;   // Kullanım süresi
  bool is_foreground;     // Ön planda mı arka planda mı
  std::string extra_info; // Ek bilgi (konum koordinatı vs)
};

// Uygulama bazlı istatistik
struct AppPermissionStats {
  std::string package_name;
  std::string app_name;
  std::unordered_map<PermissionType, int> usage_counts;
  std::unordered_map<PermissionType, uint64_t> total_duration_ms;
  uint64_t last_access_time;
  int background_access_count; // Arka plan erişim sayısı
  int risk_score;              // 0-100
};

/**
 * Permission Watcher
 * - Android AppOps API'yi kullanarak izin loglarını okur
 * - /proc ve logcat'ten ek bilgi toplar
 * - Privacy Dashboard için veri sağlar
 */
class PermissionWatcher {
public:
  PermissionWatcher();
  ~PermissionWatcher();

  // Lifecycle
  bool initialize();
  void start();
  void stop();
  bool isRunning() const { return running_.load(); }

  // İzin sorguları
  std::vector<PermissionUsage> getRecentUsage(int hours = 24);
  std::vector<PermissionUsage> getUsageByApp(const std::string &package);
  std::vector<PermissionUsage> getUsageByPermission(PermissionType type);

  // İstatistikler
  std::vector<AppPermissionStats> getAppStats();
  AppPermissionStats getStatsForApp(const std::string &package);
  int getTotalAccessCount(PermissionType type);

  // En çok erişen uygulamalar
  std::vector<std::string> getTopAccessors(PermissionType type, int count = 5);

  // Arka plan erişim uyarıları
  std::vector<PermissionUsage> getBackgroundAccesses();

  // Callback
  using UsageCallback = std::function<void(const PermissionUsage &)>;
  void setUsageCallback(UsageCallback callback) { callback_ = callback; }

  // Hassas izin uyarısı için eşik
  void setAlertThreshold(PermissionType type, int max_per_hour);

private:
  void monitorLoop();

  // AppOps sorguları
  std::vector<PermissionUsage> queryAppOps();
  std::string runAppOpsCommand(const std::string &cmd);

  // Logcat izleme
  void watchLogcat();
  PermissionUsage parseLogcatLine(const std::string &line);

  // /proc izleme (kamera, mikrofon kullanımı)
  bool isCameraInUse();
  bool isMicrophoneInUse();
  std::vector<std::string> getProcessesUsingCamera();
  std::vector<std::string> getProcessesUsingMicrophone();

  // Yardımcı fonksiyonlar
  PermissionType classifyPermission(const std::string &permission_name);
  std::string getAppName(const std::string &package_name);

  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  std::thread logcat_thread_;
  UsageCallback callback_;

  // Kullanım geçmişi (bellekte tutulan)
  std::vector<PermissionUsage> usage_history_;
  size_t max_history_size_ = 10000;

  // App stats cache
  std::unordered_map<std::string, AppPermissionStats> app_stats_;

  // Alert thresholds
  std::unordered_map<PermissionType, int> alert_thresholds_ = {
      {PermissionType::CAMERA, 10},
      {PermissionType::MICROPHONE, 20},
      {PermissionType::LOCATION, 50},
      {PermissionType::CONTACTS, 5},
      {PermissionType::SMS, 10}};

  int check_interval_ms_ = 5000;
};

} // namespace clara

#endif // CLARA_PERMISSION_WATCHER_H
