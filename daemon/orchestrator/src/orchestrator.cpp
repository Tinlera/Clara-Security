/**
 * CLARA Security - Orchestrator Implementation
 * Mikro-servisleri koordine eden ana daemon
 */

#include "../include/orchestrator.h"
#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

namespace clara {

Orchestrator &Orchestrator::getInstance() {
  static Orchestrator instance;
  return instance;
}

Orchestrator::~Orchestrator() { shutdown(); }

bool Orchestrator::initialize(const std::string &config_path) {
  syslog(LOG_INFO, "CLARA Orchestrator başlatılıyor...");

  config_path_ = config_path;
  loadConfig(config_path);

  // IPC socket oluştur
  if (!createIpcSocket()) {
    syslog(LOG_ERR, "IPC socket oluşturulamadı");
    return false;
  }

  start_time_ = std::chrono::system_clock::now().time_since_epoch().count();

  // İstatistikleri sıfırla
  stats_ = Stats{};

  syslog(LOG_INFO, "Orchestrator başarıyla başlatıldı");
  return true;
}

void Orchestrator::loadConfig(const std::string &path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    syslog(LOG_WARNING, "Config dosyası açılamadı: %s", path.c_str());
    return;
  }

  // Basit JSON parse
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  // Key-value çiftlerini çıkar
  std::regex kv_regex("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
  std::sregex_iterator it(content.begin(), content.end(), kv_regex);
  std::sregex_iterator end;

  while (it != end) {
    config_[(*it)[1].str()] = (*it)[2].str();
    ++it;
  }

  syslog(LOG_INFO, "Config yüklendi: %zu ayar", config_.size());
}

void Orchestrator::saveConfig() {
  std::ofstream file(config_path_);
  if (!file.is_open()) {
    syslog(LOG_ERR, "Config dosyası yazılamadı");
    return;
  }

  file << "{\n";
  bool first = true;
  for (const auto &pair : config_) {
    if (!first)
      file << ",\n";
    file << "  \"" << pair.first << "\": \"" << pair.second << "\"";
    first = false;
  }
  file << "\n}\n";
}

bool Orchestrator::createIpcSocket() {
  // Eski socket'i sil
  unlink(ipc_socket_path_.c_str());

  ipc_socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ipc_socket_fd_ < 0) {
    syslog(LOG_ERR, "Socket oluşturulamadı: %s", strerror(errno));
    return false;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, ipc_socket_path_.c_str(), sizeof(addr.sun_path) - 1);

  if (bind(ipc_socket_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "Socket bind hatası: %s", strerror(errno));
    close(ipc_socket_fd_);
    return false;
  }

  if (listen(ipc_socket_fd_, 10) < 0) {
    syslog(LOG_ERR, "Socket listen hatası: %s", strerror(errno));
    close(ipc_socket_fd_);
    return false;
  }

  // Socket izinlerini ayarla
  chmod(ipc_socket_path_.c_str(), 0666);

  syslog(LOG_INFO, "IPC socket oluşturuldu: %s", ipc_socket_path_.c_str());
  return true;
}

void Orchestrator::run() {
  running_ = true;

  // Servisleri başlat
  for (const auto &def : service_definitions_) {
    if (def.auto_start) {
      startService(def.name);
    }
  }

  // Thread'leri başlat
  event_thread_ = std::thread(&Orchestrator::eventLoop, this);
  health_thread_ = std::thread(&Orchestrator::healthCheckLoop, this);
  ipc_thread_ = std::thread(&Orchestrator::ipcListenerLoop, this);

  syslog(LOG_INFO, "Orchestrator çalışıyor");

  // Ana thread'i beklet
  if (event_thread_.joinable()) {
    event_thread_.join();
  }
  if (health_thread_.joinable()) {
    health_thread_.join();
  }
  if (ipc_thread_.joinable()) {
    ipc_thread_.join();
  }
}

void Orchestrator::shutdown() {
  if (!running_.load())
    return;

  syslog(LOG_INFO, "Orchestrator kapatılıyor...");
  running_ = false;

  // Tüm servisleri durdur
  for (const auto &pair : services_) {
    stopService(pair.first);
  }

  // IPC socket'i kapat
  if (ipc_socket_fd_ >= 0) {
    close(ipc_socket_fd_);
    unlink(ipc_socket_path_.c_str());
  }

  saveConfig();

  syslog(LOG_INFO, "Orchestrator kapatıldı");
}

void Orchestrator::eventLoop() {
  while (running_.load()) {
    Event event;

    {
      std::lock_guard<std::mutex> lock(event_mutex_);
      if (!event_queue_.empty()) {
        event = event_queue_.front();
        event_queue_.pop();
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        continue;
      }
    }

    processEvent(event);
    stats_.total_events_processed++;
  }
}

void Orchestrator::processEvent(const Event &event) {
  // Subscriber'lara ilet
  routeEvent(event);

  // App callback
  if (app_callback_) {
    app_callback_(event);
  }

  // İstatistikleri güncelle
  switch (event.type) {
  case EventType::SMS_THREAT:
  case EventType::FILE_THREAT:
  case EventType::NETWORK_THREAT:
  case EventType::MESSENGER_THREAT:
  case EventType::KEYLOGGER_DETECTED:
    stats_.threats_detected_today++;
    break;

  case EventType::TRACKER_BLOCKED:
    stats_.trackers_blocked_today++;
    break;

  default:
    break;
  }

  syslog(LOG_DEBUG, "Event işlendi: type=%d, source=%s",
         static_cast<int>(event.type), event.source_service.c_str());
}

void Orchestrator::routeEvent(const Event &event) {
  if (subscribers_.count(event.type) > 0) {
    for (const auto &callback : subscribers_[event.type]) {
      try {
        callback(event);
      } catch (const std::exception &e) {
        syslog(LOG_ERR, "Event callback hatası: %s", e.what());
      }
    }
  }
}

void Orchestrator::healthCheckLoop() {
  while (running_.load()) {
    {
      std::lock_guard<std::mutex> lock(services_mutex_);

      for (auto &pair : services_) {
        checkServiceHealth(pair.first);
      }
    }

    // Çalışan servis sayısını güncelle
    int running_count = 0;
    int failed_count = 0;

    for (const auto &pair : services_) {
      if (pair.second.status == ServiceStatus::RUNNING) {
        running_count++;
      } else if (pair.second.status == ServiceStatus::ERROR) {
        failed_count++;
      }
    }

    stats_.services_running = running_count;
    stats_.services_failed = failed_count;

    std::this_thread::sleep_for(std::chrono::seconds(10));
  }
}

void Orchestrator::checkServiceHealth(const std::string &name) {
  auto it = services_.find(name);
  if (it == services_.end())
    return;

  ServiceInfo &info = it->second;

  // Process hala çalışıyor mu?
  if (info.pid > 0) {
    int status;
    pid_t result = waitpid(info.pid, &status, WNOHANG);

    if (result == info.pid) {
      // Process sonlandı
      info.status = ServiceStatus::STOPPED;
      syslog(LOG_WARNING, "Servis durdu: %s (pid=%d)", name.c_str(), info.pid);

      handleServiceFailure(name);
    } else if (result == 0) {
      // Hala çalışıyor
      info.status = ServiceStatus::RUNNING;
      info.last_heartbeat =
          std::chrono::system_clock::now().time_since_epoch().count();
    }
  }
}

void Orchestrator::handleServiceFailure(const std::string &name) {
  // Servis tanımını bul
  auto def_it =
      std::find_if(service_definitions_.begin(), service_definitions_.end(),
                   [&name](const ServiceDef &def) { return def.name == name; });

  if (def_it == service_definitions_.end())
    return;

  auto &info = services_[name];

  // Otomatik yeniden başlatma
  if (def_it->auto_restart && info.restart_count < def_it->max_restarts) {
    syslog(LOG_INFO, "Servis yeniden başlatılıyor: %s (deneme %d/%d)",
           name.c_str(), info.restart_count + 1, def_it->max_restarts);

    std::this_thread::sleep_for(
        std::chrono::milliseconds(def_it->restart_delay_ms));

    info.restart_count++;
    startService(name);
  } else {
    info.status = ServiceStatus::ERROR;
    info.error_message = "Max restart sayısına ulaşıldı";

    syslog(LOG_ERR, "Servis başlatılamadı: %s", name.c_str());

    // Hata event'i
    Event event;
    event.id = std::chrono::system_clock::now().time_since_epoch().count();
    event.timestamp = event.id;
    event.type = EventType::SERVICE_ERROR;
    event.source_service = "orchestrator";
    event.target = name;
    event.message = "Servis başlatılamadı";
    event.severity = 8;

    postEvent(event);
  }
}

void Orchestrator::ipcListenerLoop() {
  while (running_.load()) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(ipc_socket_fd_, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int result =
        select(ipc_socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout);

    if (result > 0 && FD_ISSET(ipc_socket_fd_, &read_fds)) {
      struct sockaddr_un client_addr;
      socklen_t client_len = sizeof(client_addr);

      int client_fd =
          accept(ipc_socket_fd_, (struct sockaddr *)&client_addr, &client_len);

      if (client_fd >= 0) {
        handleIpcConnection(client_fd);
        close(client_fd);
      }
    }
  }
}

void Orchestrator::handleIpcConnection(int client_fd) {
  char buffer[4096];
  ssize_t bytes = read(client_fd, buffer, sizeof(buffer) - 1);

  if (bytes > 0) {
    buffer[bytes] = '\0';
    std::string message(buffer);

    std::string response = handleIpcMessage(message);

    write(client_fd, response.c_str(), response.length());
  }
}

std::string Orchestrator::handleIpcMessage(const std::string &message) {
  // Basit komut işleme
  if (message.find("status") == 0) {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"running\": " << (running_.load() ? "true" : "false") << ",\n";
    ss << "  \"services\": " << services_.size() << ",\n";
    ss << "  \"events_processed\": " << stats_.total_events_processed << ",\n";
    ss << "  \"threats_today\": " << stats_.threats_detected_today << ",\n";
    ss << "  \"trackers_blocked\": " << stats_.trackers_blocked_today << "\n";
    ss << "}\n";
    return ss.str();
  }

  if (message.find("services") == 0) {
    std::stringstream ss;
    ss << "[\n";
    bool first = true;
    for (const auto &pair : services_) {
      if (!first)
        ss << ",\n";
      ss << "  {\"name\": \"" << pair.first
         << "\", \"status\": " << static_cast<int>(pair.second.status)
         << ", \"pid\": " << pair.second.pid << "}";
      first = false;
    }
    ss << "\n]\n";
    return ss.str();
  }

  if (message.find("scan") == 0) {
    if (sendToService("security_core", "SCAN_ALL")) {
      return "{\"success\": true, \"message\": \"Tarama başlatıldı\"}\n";
    }
    return "{\"success\": false, \"error\": \"Security Core servisine "
           "ulaşılamadı\"}\n";
  }

  if (message.find("restart ") == 0) {
    std::string service_name = message.substr(8);
    service_name.erase(service_name.find_last_not_of(" \n\r\t") + 1);

    if (restartService(service_name)) {
      return "{\"success\": true}\n";
    }
    return "{\"success\": false, \"error\": \"Service not found\"}\n";
  }

  return "{\"error\": \"Unknown command\"}\n";
}

bool Orchestrator::registerService(const std::string &name,
                                   const std::string &socket_path) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  ServiceInfo info;
  info.name = name;
  info.socket_path = socket_path;
  info.status = ServiceStatus::UNKNOWN;
  info.pid = 0;
  info.restart_count = 0;

  services_[name] = info;

  syslog(LOG_INFO, "Servis kaydedildi: %s", name.c_str());
  return true;
}

bool Orchestrator::unregisterService(const std::string &name) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  if (services_.count(name) > 0) {
    stopService(name);
    services_.erase(name);
    syslog(LOG_INFO, "Servis kaldırıldı: %s", name.c_str());
    return true;
  }

  return false;
}

bool Orchestrator::startService(const std::string &name) {
  // Servis tanımını bul
  auto def_it =
      std::find_if(service_definitions_.begin(), service_definitions_.end(),
                   [&name](const ServiceDef &def) { return def.name == name; });

  if (def_it == service_definitions_.end()) {
    syslog(LOG_ERR, "Servis tanımı bulunamadı: %s", name.c_str());
    return false;
  }

  // Zaten çalışıyor mu?
  if (services_.count(name) > 0 &&
      services_[name].status == ServiceStatus::RUNNING) {
    syslog(LOG_WARNING, "Servis zaten çalışıyor: %s", name.c_str());
    return true;
  }

  // Process başlat
  pid_t pid = spawnService(name);

  if (pid > 0) {
    ServiceInfo info;
    info.name = name;
    info.socket_path = def_it->socket_path;
    info.pid = pid;
    info.status = ServiceStatus::STARTING;
    info.start_time =
        std::chrono::system_clock::now().time_since_epoch().count();
    info.restart_count = 0;

    services_[name] = info;

    // Biraz bekle ve durumu kontrol et
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    int status;
    if (waitpid(pid, &status, WNOHANG) == 0) {
      services_[name].status = ServiceStatus::RUNNING;
      syslog(LOG_INFO, "Servis başlatıldı: %s (pid=%d)", name.c_str(), pid);

      // Event gönder
      Event event;
      event.id = std::chrono::system_clock::now().time_since_epoch().count();
      event.timestamp = event.id;
      event.type = EventType::SERVICE_STARTED;
      event.source_service = "orchestrator";
      event.target = name;
      event.severity = 2;

      postEvent(event);

      return true;
    } else {
      services_[name].status = ServiceStatus::ERROR;
      syslog(LOG_ERR, "Servis hemen sonlandı: %s", name.c_str());
      return false;
    }
  }

  return false;
}

pid_t Orchestrator::spawnService(const std::string &name) {
  auto def_it =
      std::find_if(service_definitions_.begin(), service_definitions_.end(),
                   [&name](const ServiceDef &def) { return def.name == name; });

  if (def_it == service_definitions_.end())
    return -1;

  pid_t pid = fork();

  if (pid == 0) {
    // Child process
    setsid();

    // Binary'yi çalıştır
    execl(def_it->binary_path.c_str(), def_it->name.c_str(), "-f", nullptr);

    // exec başarısızsa
    syslog(LOG_ERR, "exec başarısız: %s - %s", def_it->binary_path.c_str(),
           strerror(errno));
    _exit(1);
  }

  return pid;
}

bool Orchestrator::stopService(const std::string &name) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  if (services_.count(name) == 0)
    return false;

  ServiceInfo &info = services_[name];

  if (info.pid > 0) {
    // SIGTERM gönder
    kill(info.pid, SIGTERM);

    // Biraz bekle
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Hala çalışıyorsa SIGKILL
    int status;
    if (waitpid(info.pid, &status, WNOHANG) == 0) {
      kill(info.pid, SIGKILL);
      waitpid(info.pid, &status, 0);
    }

    info.status = ServiceStatus::STOPPED;
    info.pid = 0;

    syslog(LOG_INFO, "Servis durduruldu: %s", name.c_str());

    // Event gönder
    Event event;
    event.id = std::chrono::system_clock::now().time_since_epoch().count();
    event.timestamp = event.id;
    event.type = EventType::SERVICE_STOPPED;
    event.source_service = "orchestrator";
    event.target = name;
    event.severity = 3;

    postEvent(event);

    return true;
  }

  return false;
}

bool Orchestrator::restartService(const std::string &name) {
  stopService(name);
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  return startService(name);
}

ServiceInfo Orchestrator::getServiceInfo(const std::string &name) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  if (services_.count(name) > 0) {
    return services_[name];
  }

  return ServiceInfo{};
}

std::vector<ServiceInfo> Orchestrator::getAllServices() {
  std::lock_guard<std::mutex> lock(services_mutex_);

  std::vector<ServiceInfo> result;
  for (const auto &pair : services_) {
    result.push_back(pair.second);
  }

  return result;
}

ServiceStatus Orchestrator::getServiceStatus(const std::string &name) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  if (services_.count(name) > 0) {
    return services_[name].status;
  }

  return ServiceStatus::UNKNOWN;
}

bool Orchestrator::isServiceRunning(const std::string &name) {
  return getServiceStatus(name) == ServiceStatus::RUNNING;
}

void Orchestrator::postEvent(const Event &event) {
  std::lock_guard<std::mutex> lock(event_mutex_);
  event_queue_.push(event);
}

void Orchestrator::subscribeToEvents(
    EventType type, std::function<void(const Event &)> callback) {
  subscribers_[type].push_back(callback);
}

void Orchestrator::unsubscribeFromEvents(EventType type) {
  subscribers_.erase(type);
}

bool Orchestrator::sendToService(const std::string &service_name,
                                 const std::string &message) {
  if (service_sockets_.count(service_name) == 0) {
    if (!connectToService(service_name)) {
      return false;
    }
  }

  int fd = service_sockets_[service_name];
  ssize_t sent = write(fd, message.c_str(), message.length());

  return sent == static_cast<ssize_t>(message.length());
}

std::string Orchestrator::queryService(const std::string &service_name,
                                       const std::string &query) {
  if (!sendToService(service_name, query)) {
    return "";
  }

  int fd = service_sockets_[service_name];
  char buffer[4096];
  ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);

  if (bytes > 0) {
    buffer[bytes] = '\0';
    return std::string(buffer);
  }

  return "";
}

bool Orchestrator::connectToService(const std::string &name) {
  if (services_.count(name) == 0)
    return false;

  const std::string &socket_path = services_[name].socket_path;

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return false;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return false;
  }

  service_sockets_[name] = fd;
  return true;
}

void Orchestrator::setAppCallback(std::function<void(const Event &)> callback) {
  app_callback_ = callback;
}

void Orchestrator::notifyApp(const Event &event) {
  if (app_callback_) {
    app_callback_(event);
  }
}

void Orchestrator::reloadConfig() {
  loadConfig(config_path_);
  syslog(LOG_INFO, "Config yeniden yüklendi");
}

std::string Orchestrator::getConfig(const std::string &key) {
  if (config_.count(key) > 0) {
    return config_[key];
  }
  return "";
}

void Orchestrator::setConfig(const std::string &key, const std::string &value) {
  config_[key] = value;
  saveConfig();
}

Orchestrator::Stats Orchestrator::getStats() {
  auto now = std::chrono::system_clock::now().time_since_epoch().count();
  stats_.uptime_seconds = (now - start_time_) / 1000000000;

  return stats_;
}

} // namespace clara
