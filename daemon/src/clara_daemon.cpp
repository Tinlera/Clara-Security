/**
 * CLARA Security - Clara Daemon Implementation
 */

#include "../include/clara_daemon.h"
#include "../include/ai_engine.h"
#include <chrono>
#include <fstream>
#include <regex>
#include <sstream>
#include <syslog.h>

namespace clara {

// ============================================================================
// Database Implementation (must be defined before ClaraDaemon methods that use
// it)
// ============================================================================

class Database : public IDatabase {
public:
  bool initialize(const std::string &path) override {
    db_path_ = path;
    events_file_ = path + "/events.log";
    threats_file_ = path + "/threats.log";

    // Dosyaları oluştur (yoksa)
    std::ofstream(events_file_, std::ios::app).close();
    std::ofstream(threats_file_, std::ios::app).close();

    syslog(LOG_INFO, "Database initialized: %s", path.c_str());
    return true;
  }

  void logEvent(const SecurityEvent &event) override {
    std::ofstream file(events_file_, std::ios::app);
    if (file.is_open()) {
      // JSON-like format
      file << "{\"id\":" << event.id << ",\"ts\":" << event.timestamp
           << ",\"type\":" << static_cast<int>(event.type)
           << ",\"level\":" << static_cast<int>(event.level) << ",\"src\":\""
           << event.source << "\""
           << ",\"desc\":\"" << event.description << "\"}\n";
    }
    syslog(LOG_DEBUG, "Event logged: %s", event.description.c_str());
  }

  void logThreat(const ThreatInfo &threat) override {
    std::ofstream file(threats_file_, std::ios::app);
    if (file.is_open()) {
      file << "{\"type\":\"" << threat.type << "\""
           << ",\"level\":" << static_cast<int>(threat.level)
           << ",\"confidence\":" << threat.confidence << ",\"src\":\""
           << threat.source << "\""
           << ",\"desc\":\"" << threat.description << "\"}\n";
    }
    syslog(LOG_DEBUG, "Threat logged: %s", threat.description.c_str());
  }

  std::vector<SecurityEvent> getRecentEvents(int count) override {
    std::vector<SecurityEvent> events;
    std::ifstream file(events_file_);
    std::string line;
    std::vector<std::string> lines;

    while (std::getline(file, line)) {
      lines.push_back(line);
    }

    // Son 'count' satırı al
    int start = std::max(0, static_cast<int>(lines.size()) - count);
    for (size_t i = start; i < lines.size(); i++) {
      SecurityEvent e;
      e.description = lines[i]; // Basitleştirilmiş
      events.push_back(e);
    }
    return events;
  }

  std::vector<ThreatInfo> getRecentThreats(int count) override {
    std::vector<ThreatInfo> threats;
    std::ifstream file(threats_file_);
    std::string line;
    std::vector<std::string> lines;

    while (std::getline(file, line)) {
      lines.push_back(line);
    }

    int start = std::max(0, static_cast<int>(lines.size()) - count);
    for (size_t i = start; i < lines.size(); i++) {
      ThreatInfo t;
      t.description = lines[i];
      threats.push_back(t);
    }
    return threats;
  }

  void cleanup(int retention_days) override {
    // Basit cleanup - dosya boyutunu kontrol et
    (void)retention_days;

    // 10MB üzerindeyse dosyayı temizle
    std::ifstream in(events_file_, std::ios::ate | std::ios::binary);
    if (in.tellg() > 10 * 1024 * 1024) {
      std::ofstream(events_file_, std::ios::trunc).close();
      syslog(LOG_INFO, "Events log temizlendi");
    }

    std::ifstream in2(threats_file_, std::ios::ate | std::ios::binary);
    if (in2.tellg() > 10 * 1024 * 1024) {
      std::ofstream(threats_file_, std::ios::trunc).close();
      syslog(LOG_INFO, "Threats log temizlendi");
    }
  }

private:
  std::string db_path_;
  std::string events_file_;
  std::string threats_file_;
};

// ============================================================================
// ThreatResponse Implementation (must be defined before ClaraDaemon methods)
// ============================================================================

class ThreatResponse : public IThreatResponse {
public:
  void handleThreat(const ThreatInfo &threat) override {
    syslog(LOG_WARNING, "Tehdit tespit edildi: %s (seviye: %d)",
           threat.description.c_str(), static_cast<int>(threat.level));

    if (!autonomous_mode_) {
      // Sadece log ve bildirim
      sendNotification(threat);
      return;
    }

    // Otonom mod - risk seviyesine göre aksiyon al
    for (const auto &action : threat.recommended_actions) {
      if (shouldExecuteAction(action, threat.level)) {
        executeAction(action, threat.source);
      }
    }
  }

  void executeAction(ActionType action, const std::string &target) override {
    switch (action) {
    case ActionType::LOG:
      syslog(LOG_INFO, "ACTION LOG: %s", target.c_str());
      break;

    case ActionType::NOTIFY: {
      syslog(LOG_INFO, "ACTION NOTIFY: %s", target.c_str());
      // Android notification - cmd kullanarak
      std::string cmd = "cmd notification post -S messaging -t 'CLARA "
                        "Security' 'clara_threat' '" +
                        target + "'";
      system(cmd.c_str());
      break;
    }

    case ActionType::QUARANTINE: {
      syslog(LOG_WARNING, "ACTION QUARANTINE: %s", target.c_str());
      // Dosyayı karantina klasörüne taşı
      std::string quarantine_dir = "/data/clara/quarantine/";
      std::string filename = target.substr(target.find_last_of("/") + 1);
      std::string cmd =
          "mv '" + target + "' '" + quarantine_dir + filename + ".quarantine'";
      if (system(cmd.c_str()) == 0) {
        syslog(LOG_INFO, "Dosya karantinaya alındı: %s", target.c_str());
      }
      break;
    }

    case ActionType::BLOCK: {
      syslog(LOG_WARNING, "ACTION BLOCK: %s", target.c_str());
      // Uygulamayı zorla durdur (am force-stop)
      std::string cmd = "am force-stop " + target;
      system(cmd.c_str());
      break;
    }

    case ActionType::REVOKE_PERMISSION: {
      syslog(LOG_WARNING, "ACTION REVOKE: %s", target.c_str());
      // İzni kaldır (format: package:permission)
      size_t sep = target.find(':');
      if (sep != std::string::npos) {
        std::string pkg = target.substr(0, sep);
        std::string perm = target.substr(sep + 1);
        std::string cmd = "pm revoke " + pkg + " " + perm;
        system(cmd.c_str());
      }
      break;
    }

    case ActionType::ISOLATE_NETWORK: {
      syslog(LOG_WARNING, "ACTION ISOLATE: %s", target.c_str());
      // iptables ile ağ erişimini kes
      std::string uid_cmd = "dumpsys package " + target +
                            " | grep userId= | head -1 | cut -d= -f2";
      FILE *pipe = popen(uid_cmd.c_str(), "r");
      if (pipe) {
        char uid_buf[32];
        if (fgets(uid_buf, sizeof(uid_buf), pipe)) {
          std::string uid(uid_buf);
          uid.erase(uid.find_last_not_of(" \n\r\t") + 1);
          // iptables kuralı ekle
          std::string block_cmd =
              "iptables -A OUTPUT -m owner --uid-owner " + uid + " -j DROP";
          system(block_cmd.c_str());
          syslog(LOG_INFO, "Network izole edildi: %s (UID: %s)", target.c_str(),
                 uid.c_str());
        }
        pclose(pipe);
      }
      break;
    }

    case ActionType::KILL_PROCESS: {
      syslog(LOG_WARNING, "ACTION KILL: %s", target.c_str());
      // Process'i pkill ile öldür
      std::string cmd = "pkill -9 -f '" + target + "'";
      system(cmd.c_str());
      // veya am force-stop kullan
      std::string am_cmd = "am force-stop " + target;
      system(am_cmd.c_str());
      break;
    }
    }
  }

  void setAutonomousMode(bool enabled) override {
    autonomous_mode_ = enabled;
    syslog(LOG_INFO, "Otonom mod: %s", enabled ? "aktif" : "pasif");
  }

  void setRiskThreshold(ThreatLevel level, float threshold) override {
    risk_thresholds_[level] = threshold;
  }

private:
  bool shouldExecuteAction(ActionType action, ThreatLevel level) {
    // Düşük risk için sadece log
    if (level <= ThreatLevel::LOW && action != ActionType::LOG) {
      return false;
    }

    // Orta risk için log + notify
    if (level == ThreatLevel::MEDIUM && action != ActionType::LOG &&
        action != ActionType::NOTIFY) {
      return false;
    }

    // Yüksek ve kritik için tüm aksiyonlar
    return true;
  }

  void sendNotification(const ThreatInfo &threat) {
    // Android notification via su ile am komutu
    // TODO: Proper notification implementation
    syslog(LOG_INFO, "Bildirim gönderildi: %s", threat.description.c_str());
  }

  bool autonomous_mode_ = false;
  std::unordered_map<ThreatLevel, float> risk_thresholds_;
};

// ============================================================================
// ClaraDaemon Implementation
// ============================================================================

ClaraDaemon &ClaraDaemon::getInstance() {
  static ClaraDaemon instance;
  return instance;
}

ClaraDaemon::~ClaraDaemon() { shutdown(); }

bool ClaraDaemon::initialize(const std::string &config_path) {
  syslog(LOG_INFO, "CLARA Daemon başlatılıyor...");

  // Konfigürasyonu yükle
  loadConfig(config_path);

  // AI Engine başlat
  ai_engine_ = std::make_shared<AiEngine>();
  if (!ai_engine_->loadModels(config_.count("model_dir")
                                  ? config_["model_dir"]
                                  : "/data/clara/cache")) {
    syslog(LOG_WARNING, "AI modelleri yüklenemedi, kural tabanlı mod aktif");
  }

  // Database başlat
  database_ = std::make_shared<Database>();
  std::string db_path =
      config_.count("db_path") ? config_["db_path"] : "/data/clara/database";
  if (!database_->initialize(db_path)) {
    syslog(LOG_ERR, "Database başlatılamadı: %s", db_path.c_str());
    return false;
  }

  // Threat Response başlat
  threat_response_ = std::make_shared<ThreatResponse>();

  syslog(LOG_INFO, "CLARA Daemon başarıyla başlatıldı");
  return true;
}

void ClaraDaemon::loadConfig(const std::string &path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    syslog(LOG_WARNING,
           "Config dosyası açılamadı: %s, varsayılanlar kullanılıyor",
           path.c_str());
    return;
  }

  // Basit JSON parsing (sadece string key-value çiftleri)
  std::string line;
  std::regex kv_regex("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");

  while (std::getline(file, line)) {
    std::smatch match;
    if (std::regex_search(line, match, kv_regex)) {
      config_[match[1].str()] = match[2].str();
    }
  }

  syslog(LOG_INFO, "Config yüklendi: %zu ayar", config_.size());
}

void ClaraDaemon::run() {
  if (running_.load()) {
    syslog(LOG_WARNING, "Daemon zaten çalışıyor");
    return;
  }

  running_ = true;

  // Modülleri başlat
  for (auto &module : modules_) {
    module->start();
  }

  // Event loop başlat
  event_thread_ = std::thread(&ClaraDaemon::eventLoop, this);

  syslog(LOG_INFO, "CLARA Daemon çalışmaya başladı");
}

void ClaraDaemon::shutdown() {
  if (!running_.load()) {
    return;
  }

  syslog(LOG_INFO, "CLARA Daemon kapatılıyor...");

  running_ = false;

  // Modülleri durdur
  for (auto &module : modules_) {
    module->stop();
  }

  // Event thread'i bekle
  if (event_thread_.joinable()) {
    event_thread_.join();
  }

  syslog(LOG_INFO, "CLARA Daemon kapatıldı");
}

void ClaraDaemon::registerModule(std::shared_ptr<IModule> module) {
  modules_.push_back(module);
  syslog(LOG_INFO, "Modül kaydedildi: %s", module->getName().c_str());
}

std::shared_ptr<IModule> ClaraDaemon::getModule(const std::string &name) {
  for (auto &module : modules_) {
    if (module->getName() == name) {
      return module;
    }
  }
  return nullptr;
}

void ClaraDaemon::postEvent(const SecurityEvent &event) {
  std::lock_guard<std::mutex> lock(queue_mutex_);
  event_queue_.push(event);
}

void ClaraDaemon::setEventCallback(EventCallback callback) {
  event_callback_ = callback;
}

void ClaraDaemon::eventLoop() {
  while (running_.load()) {
    SecurityEvent event;
    bool has_event = false;

    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      if (!event_queue_.empty()) {
        event = event_queue_.front();
        event_queue_.pop();
        has_event = true;
      }
    }

    if (has_event) {
      processEvent(event);
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
}

void ClaraDaemon::processEvent(const SecurityEvent &event) {
  // Callback çağır
  if (event_callback_) {
    event_callback_(event);
  }

  // Database'e kaydet
  if (database_) {
    database_->logEvent(event);
  }

  // Yüksek riskli olayları threat response'a gönder
  if (event.level >= ThreatLevel::MEDIUM && threat_response_) {
    ThreatInfo threat;
    threat.level = event.level;
    threat.source = event.source;
    threat.description = event.description;

    threat_response_->handleThreat(threat);
  }
}

std::string ClaraDaemon::getStatus() const {
  std::stringstream ss;
  ss << "CLARA Security Daemon v" << VERSION << "\n";
  ss << "Durum: " << (running_.load() ? "Çalışıyor" : "Durduruldu") << "\n";
  ss << "Aktif Modüller: " << modules_.size() << "\n";

  for (const auto &module : modules_) {
    ss << "  - " << module->getName() << ": "
       << (module->isRunning() ? "Aktif" : "Pasif") << "\n";
  }

  return ss.str();
}

} // namespace clara
