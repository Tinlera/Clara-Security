/**
 * CLARA Security Daemon - Main Header
 * AI-Powered Autonomous Security System
 * 
 * Platform: Android 15 (API 36)
 * Target: MediaTek Dimensity 8400 Ultra
 */

#ifndef CLARA_DAEMON_H
#define CLARA_DAEMON_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <unordered_map>

namespace clara {

// Versiyon bilgisi
constexpr const char* VERSION = "0.1.0";
constexpr int VERSION_CODE = 1;

// Tehdit seviyeleri
enum class ThreatLevel {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Olay türleri
enum class EventType {
    SMS_RECEIVED,
    SMS_BLOCKED,
    FILE_CREATED,
    FILE_MODIFIED,
    FILE_SCANNED,
    FILE_QUARANTINED,
    APP_INSTALLED,
    APP_LAUNCHED,
    APP_SUSPICIOUS,
    NETWORK_ANOMALY,
    PERMISSION_USED,
    THREAT_DETECTED,
    THREAT_MITIGATED
};

// Aksiyon türleri
enum class ActionType {
    LOG,
    NOTIFY,
    QUARANTINE,
    BLOCK,
    REVOKE_PERMISSION,
    ISOLATE_NETWORK,
    KILL_PROCESS
};

// Güvenlik olayı yapısı
struct SecurityEvent {
    uint64_t id;
    uint64_t timestamp;
    EventType type;
    ThreatLevel level;
    std::string source;
    std::string description;
    std::string metadata;  // JSON formatında ek veri
    bool handled;
};

// Tehdit bilgisi
struct ThreatInfo {
    std::string id;
    ThreatLevel level;
    std::string type;
    std::string source;
    std::string description;
    float confidence;
    std::vector<ActionType> recommended_actions;
    std::string raw_data;
};

// SMS bilgisi
struct SmsInfo {
    std::string sender;
    std::string body;
    uint64_t timestamp;
    bool is_read;
    int thread_id;
};

// Dosya bilgisi
struct FileInfo {
    std::string path;
    std::string name;
    std::string extension;
    uint64_t size;
    uint64_t modified_time;
    std::string sha256_hash;
    std::string mime_type;
    bool is_apk;
};

// Uygulama bilgisi
struct AppInfo {
    std::string package_name;
    std::string app_name;
    int uid;
    int target_sdk;
    std::vector<std::string> permissions;
    uint64_t install_time;
    uint64_t last_used;
    bool is_system;
};

// Ağ akışı bilgisi
struct NetworkFlow {
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string protocol;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    int uid;
    std::string app_name;
};

// Callback tanımları
using EventCallback = std::function<void(const SecurityEvent&)>;
using ThreatCallback = std::function<void(const ThreatInfo&)>;

/**
 * Ana modül arayüzü
 */
class IModule {
public:
    virtual ~IModule() = default;
    
    virtual const std::string& getName() const = 0;
    virtual bool initialize() = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool isRunning() const = 0;
    virtual void setEventCallback(EventCallback callback) = 0;
};

/**
 * AI Inference Engine arayüzü
 */
class IAiEngine {
public:
    virtual ~IAiEngine() = default;
    
    // SMS phishing analizi
    virtual ThreatInfo analyzeSms(const SmsInfo& sms) = 0;
    
    // Dosya/APK malware analizi
    virtual ThreatInfo analyzeFile(const FileInfo& file) = 0;
    
    // Ağ anomali analizi
    virtual ThreatInfo analyzeNetworkFlow(const NetworkFlow& flow) = 0;
    
    // Uygulama davranış analizi
    virtual ThreatInfo analyzeAppBehavior(const AppInfo& app, 
                                           const std::vector<std::string>& recent_actions) = 0;
    
    // Model yükleme/güncelleme
    virtual bool loadModels(const std::string& model_dir) = 0;
    virtual bool updateModel(const std::string& model_name, const std::string& path) = 0;
};

/**
 * Tehdit yanıt motoru arayüzü
 */
class IThreatResponse {
public:
    virtual ~IThreatResponse() = default;
    
    virtual void handleThreat(const ThreatInfo& threat) = 0;
    virtual void executeAction(ActionType action, const std::string& target) = 0;
    virtual void setAutonomousMode(bool enabled) = 0;
    virtual void setRiskThreshold(ThreatLevel level, float threshold) = 0;
};

/**
 * Database arayüzü
 */
class IDatabase {
public:
    virtual ~IDatabase() = default;
    
    virtual bool initialize(const std::string& path) = 0;
    virtual void logEvent(const SecurityEvent& event) = 0;
    virtual void logThreat(const ThreatInfo& threat) = 0;
    virtual std::vector<SecurityEvent> getRecentEvents(int count) = 0;
    virtual std::vector<ThreatInfo> getRecentThreats(int count) = 0;
    virtual void cleanup(int retention_days) = 0;
};

/**
 * Ana daemon sınıfı
 */
class ClaraDaemon {
public:
    static ClaraDaemon& getInstance();
    
    // Lifecycle
    bool initialize(const std::string& config_path);
    void run();
    void shutdown();
    
    // Modül yönetimi
    void registerModule(std::shared_ptr<IModule> module);
    std::shared_ptr<IModule> getModule(const std::string& name);
    
    // Olay işleme
    void postEvent(const SecurityEvent& event);
    void setEventCallback(EventCallback callback);
    
    // Durum sorgulama
    bool isRunning() const { return running_.load(); }
    std::string getStatus() const;
    
    // AI Engine
    std::shared_ptr<IAiEngine> getAiEngine() { return ai_engine_; }
    
    // Threat Response
    std::shared_ptr<IThreatResponse> getThreatResponse() { return threat_response_; }
    
    // Database
    std::shared_ptr<IDatabase> getDatabase() { return database_; }

private:
    ClaraDaemon() = default;
    ~ClaraDaemon();
    
    ClaraDaemon(const ClaraDaemon&) = delete;
    ClaraDaemon& operator=(const ClaraDaemon&) = delete;
    
    void eventLoop();
    void processEvent(const SecurityEvent& event);
    void loadConfig(const std::string& path);
    
    std::atomic<bool> running_{false};
    std::vector<std::shared_ptr<IModule>> modules_;
    std::queue<SecurityEvent> event_queue_;
    std::mutex queue_mutex_;
    std::thread event_thread_;
    
    std::shared_ptr<IAiEngine> ai_engine_;
    std::shared_ptr<IThreatResponse> threat_response_;
    std::shared_ptr<IDatabase> database_;
    
    EventCallback event_callback_;
    std::unordered_map<std::string, std::string> config_;
};

} // namespace clara

#endif // CLARA_DAEMON_H
