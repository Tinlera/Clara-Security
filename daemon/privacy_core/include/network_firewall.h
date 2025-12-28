/**
 * CLARA Security - Network Firewall
 *
 * Uygulama bazlı ağ erişim kontrolü.
 * iptables kullanarak WiFi ve Mobile Data erişimini yönetir.
 */

#ifndef CLARA_NETWORK_FIREWALL_H
#define CLARA_NETWORK_FIREWALL_H

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace clara {

/**
 * Güvenlik duvarı kural tipi
 */
enum class FirewallAction {
  ALLOW,     // İzin ver
  DENY,      // Engelle
  LOG_ONLY,  // Sadece logla
  QUARANTINE // Karantina (tüm erişim engelli)
};

/**
 * Ağ tipi
 */
enum class NetworkType {
  ALL,    // Tüm ağlar
  WIFI,   // Sadece WiFi
  MOBILE, // Sadece mobil data
  VPN     // VPN
};

/**
 * Güvenlik duvarı kuralı
 */
struct FirewallRule {
  std::string package_name;
  int uid;                      // Android UID
  FirewallAction wifi_action;   // WiFi için kural
  FirewallAction mobile_action; // Mobile için kural
  bool is_system_app;
  bool is_user_defined; // Kullanıcı mı tanımladı
  int64_t created_time;
  int64_t block_count; // Kaç kez engellendi
  int64_t last_block_time;
};

/**
 * Ağ trafiği istatistiği
 */
struct AppNetworkStats {
  std::string package_name;
  int uid;
  int64_t wifi_rx_bytes;   // WiFi indirilen
  int64_t wifi_tx_bytes;   // WiFi yüklenen
  int64_t mobile_rx_bytes; // Mobile indirilen
  int64_t mobile_tx_bytes; // Mobile yüklenen
  int64_t last_activity;
};

/**
 * Network Firewall sınıfı
 */
class NetworkFirewall {
public:
  NetworkFirewall();
  ~NetworkFirewall();

  /**
   * Firewall'ı başlat ve kuralları uygula
   */
  bool initialize();

  /**
   * Firewall'ı durdur ve kuralları temizle
   */
  void stop();

  /**
   * Uygulama için kural ekle/güncelle
   */
  bool setRule(const std::string &package_name, FirewallAction wifi_action,
               FirewallAction mobile_action);

  /**
   * Uygulamanın kuralını al
   */
  FirewallRule getRule(const std::string &package_name);

  /**
   * Tüm kuralları al
   */
  std::vector<FirewallRule> getAllRules();

  /**
   * Kuralı sil (varsayılana dön)
   */
  bool removeRule(const std::string &package_name);

  /**
   * Tüm kuralları temizle
   */
  void clearAllRules();

  /**
   * Uygulamayı hemen engelle (acil)
   */
  bool blockImmediately(const std::string &package_name);

  /**
   * Uygulamanın engelini kaldır
   */
  bool unblock(const std::string &package_name);

  /**
   * Uygulama ağa erişebilir mi?
   */
  bool canAccess(const std::string &package_name, NetworkType network);

  /**
   * UID'den package name bul
   */
  std::string getPackageByUid(int uid);

  /**
   * Package name'den UID bul
   */
  int getUidByPackage(const std::string &package_name);

  /**
   * Ağ istatistiklerini al
   */
  std::vector<AppNetworkStats> getNetworkStats();

  /**
   * Belirli uygulamanın istatistiğini al
   */
  AppNetworkStats getAppStats(const std::string &package_name);

  /**
   * Kuralları dosyadan yükle
   */
  void loadRules();

  /**
   * Kuralları dosyaya kaydet
   */
  void saveRules();

  /**
   * Boot'ta kuralları uygula
   */
  void applyAllRules();

  /**
   * İstatistikler
   */
  struct Stats {
    int total_rules;
    int blocked_apps;
    int64_t total_blocks;
    int64_t last_block_time;
  };
  Stats getStats() const;

  /**
   * Kural değişikliği callback'i
   */
  using RuleChangeCallback = std::function<void(const FirewallRule &)>;
  void setRuleChangeCallback(RuleChangeCallback callback);

private:
  bool initialized_;
  std::unordered_map<std::string, FirewallRule> rules_;
  RuleChangeCallback callback_;
  Stats stats_;

  // iptables chain adı
  static const std::string CHAIN_NAME;
  static const std::string RULES_FILE;

  // Yardımcı fonksiyonlar
  std::string executeCommand(const std::string &cmd);
  bool executeiptables(const std::string &rule);
  bool createChain();
  bool deleteChain();
  bool applyRule(const FirewallRule &rule);
  bool removeIptablesRule(const FirewallRule &rule);
  void loadSystemApps();
};

} // namespace clara

#endif // CLARA_NETWORK_FIREWALL_H
