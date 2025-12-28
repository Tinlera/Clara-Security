/**
 * CLARA Security - Orchestrator Daemon
 * Mikro-servisleri koordine eden ana daemon
 */

#ifndef CLARA_ORCHESTRATOR_H
#define CLARA_ORCHESTRATOR_H

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unordered_map>
#include <vector>

namespace clara {

// Servis durumları
enum class ServiceStatus {
  UNKNOWN,
  STARTING,
  RUNNING,
  STOPPING,
  STOPPED,
  ERROR
};

// Servis bilgisi
struct ServiceInfo {
  std::string name;
  std::string socket_path;
  pid_t pid;
  ServiceStatus status;
  uint64_t start_time;
  uint64_t last_heartbeat;
  int restart_count;
  std::string error_message;
};

// Event türleri
enum class EventType {
  // Güvenlik olayları
  SMS_THREAT,
  FILE_THREAT,
  NETWORK_THREAT,
  MESSENGER_THREAT,
  KEYLOGGER_DETECTED,

  // Gizlilik olayları
  PERMISSION_ACCESS,
  TRACKER_BLOCKED,

  // Uygulama olayları
  APP_LOCK_TRIGGERED,
  ROOT_DETECTION_ATTEMPT,

  // Sistem olayları
  SERVICE_STARTED,
  SERVICE_STOPPED,
  SERVICE_ERROR,
  CONFIG_CHANGED
};

// Olay yapısı
struct Event {
  uint64_t id;
  uint64_t timestamp;
  EventType type;
  std::string source_service;
  std::string target;
  std::string message;
  std::string data; // JSON formatında ek veri
  int severity;     // 0-10
};

/**
 * Orchestrator
 * - Tüm mikro-servisleri başlatır ve yönetir
 * - Unix socket üzerinden IPC sağlar
 * - Event routing yapar
 * - Health monitoring
 * - Android App ile iletişim (AIDL)
 */
class Orchestrator {
public:
  static Orchestrator &getInstance();

  // Lifecycle
  bool initialize(const std::string &config_path);
  void run();
  void shutdown();
  bool isRunning() const { return running_.load(); }

  // Servis yönetimi
  bool registerService(const std::string &name, const std::string &socket_path);
  bool unregisterService(const std::string &name);
  bool startService(const std::string &name);
  bool stopService(const std::string &name);
  bool restartService(const std::string &name);

  // Servis sorgulama
  ServiceInfo getServiceInfo(const std::string &name);
  std::vector<ServiceInfo> getAllServices();
  ServiceStatus getServiceStatus(const std::string &name);
  bool isServiceRunning(const std::string &name);

  // Event sistemi
  void postEvent(const Event &event);
  void subscribeToEvents(EventType type,
                         std::function<void(const Event &)> callback);
  void unsubscribeFromEvents(EventType type);

  // IPC
  bool sendToService(const std::string &service_name,
                     const std::string &message);
  std::string queryService(const std::string &service_name,
                           const std::string &query);

  // Android App iletişimi
  void setAppCallback(std::function<void(const Event &)> callback);
  void notifyApp(const Event &event);

  // Konfigürasyon
  void reloadConfig();
  std::string getConfig(const std::string &key);
  void setConfig(const std::string &key, const std::string &value);

  // İstatistikler
  struct Stats {
    uint64_t uptime_seconds;
    int total_events_processed;
    int services_running;
    int services_failed;
    int threats_detected_today;
    int trackers_blocked_today;
  };
  Stats getStats();

private:
  Orchestrator() = default;
  ~Orchestrator();

  Orchestrator(const Orchestrator &) = delete;
  Orchestrator &operator=(const Orchestrator &) = delete;

  // Ana döngüler
  void eventLoop();
  void healthCheckLoop();
  void ipcListenerLoop();

  // Servis başlatma
  pid_t spawnService(const std::string &name);
  bool connectToService(const std::string &name);

  // Health check
  void checkServiceHealth(const std::string &name);
  void handleServiceFailure(const std::string &name);

  // Event işleme
  void processEvent(const Event &event);
  void routeEvent(const Event &event);

  // IPC
  bool createIpcSocket();
  void handleIpcConnection(int client_fd);
  std::string handleIpcMessage(const std::string &message);

  // Konfigürasyon yükleme
  void loadConfig(const std::string &path);
  void saveConfig();

  std::atomic<bool> running_{false};

  // Thread'ler
  std::thread event_thread_;
  std::thread health_thread_;
  std::thread ipc_thread_;

  // Servisler
  std::unordered_map<std::string, ServiceInfo> services_;
  std::unordered_map<std::string, int>
      service_sockets_; // Servis socket fd'leri
  std::mutex services_mutex_;

  // Event kuyruğu
  std::queue<Event> event_queue_;
  std::mutex event_mutex_;

  // Event subscribers
  std::unordered_map<EventType, std::vector<std::function<void(const Event &)>>>
      subscribers_;

  // App callback
  std::function<void(const Event &)> app_callback_;

  // IPC socket
  int ipc_socket_fd_ = -1;
  std::string ipc_socket_path_ = "/data/clara/orchestrator.sock";

  // Konfigürasyon
  std::unordered_map<std::string, std::string> config_;
  std::string config_path_;

  // İstatistikler
  Stats stats_;
  uint64_t start_time_;

  // Servis tanımları
  struct ServiceDef {
    std::string name;
    std::string binary_path;
    std::string socket_path;
    bool auto_start;
    bool auto_restart;
    int restart_delay_ms;
    int max_restarts;
  };

  std::vector<ServiceDef> service_definitions_ = {
      {"security_core",
       "/data/adb/modules/clara_security/system/bin/clara_security_core",
       "/data/clara/security_core.sock", true, true, 5000, 5},
      {"privacy_core",
       "/data/adb/modules/clara_security/system/bin/clara_privacy_core",
       "/data/clara/privacy_core.sock", true, true, 5000, 5},
      {"app_manager",
       "/data/adb/modules/clara_security/system/bin/clara_app_manager",
       "/data/clara/app_manager.sock", true, true, 5000, 5}};
};

} // namespace clara

#endif // CLARA_ORCHESTRATOR_H
