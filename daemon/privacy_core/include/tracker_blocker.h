/**
 * CLARA Security - Tracker Blocker
 * Reklam ve izleme trackerlarını engeller (hosts file tabanlı)
 */

#ifndef CLARA_TRACKER_BLOCKER_H
#define CLARA_TRACKER_BLOCKER_H

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clara {

// Engelleme kategorileri
enum class BlockCategory {
  ADS,       // Reklamlar
  ANALYTICS, // Analitik/İzleme
  SOCIAL,    // Sosyal medya trackerları
  MALWARE,   // Zararlı domainler
  ADULT,     // Yetişkin içerik (opsiyonel)
  GAMBLING,  // Kumar siteleri (opsiyonel)
  CUSTOM     // Kullanıcı tanımlı
};

// Engellenen domain bilgisi
struct BlockedDomain {
  std::string domain;
  BlockCategory category;
  int block_count; // Kaç kez engellendi
  uint64_t last_blocked_time;
  std::string source_list; // Hangi listeden geldi
};

// İstatistikler
struct BlockerStats {
  int total_blocked_today;
  int total_blocked_all_time;
  std::unordered_map<BlockCategory, int> blocks_by_category;
  std::unordered_map<std::string, int> top_blocked_domains;
  std::unordered_map<std::string, int> top_blocking_apps;
};

/**
 * Tracker Blocker
 * - /system/etc/hosts dosyasını yönetir
 * - Birden fazla blocklist kaynağını birleştirir
 * - DNS sorgularını loglar (opsiyonel)
 */
class TrackerBlocker {
public:
  TrackerBlocker();
  ~TrackerBlocker();

  // Lifecycle
  bool initialize();
  void start();
  void stop();
  bool isRunning() const { return running_.load(); }

  // Hosts dosyası yönetimi
  bool updateHostsFile();
  bool restoreOriginalHosts();
  int getBlockedDomainCount();

  // Blocklist yönetimi
  void addBlocklist(const std::string &url, BlockCategory category);
  void removeBlocklist(const std::string &url);
  bool updateBlocklists(); // Tüm listeleri güncelle

  // Manuel domain ekleme/çıkarma
  void blockDomain(const std::string &domain, BlockCategory category);
  void unblockDomain(const std::string &domain);
  bool isDomainBlocked(const std::string &domain);

  // Whitelist
  void addToWhitelist(const std::string &domain);
  void removeFromWhitelist(const std::string &domain);
  bool isWhitelisted(const std::string &domain);

  // Kategori yönetimi
  void enableCategory(BlockCategory category);
  void disableCategory(BlockCategory category);
  bool isCategoryEnabled(BlockCategory category);

  // İstatistikler
  BlockerStats getStats();
  std::vector<BlockedDomain> getRecentlyBlocked(int count = 50);

  // DNS log callback (VPN modunda kullanılacak)
  using DnsCallback =
      std::function<void(const std::string &domain, bool blocked)>;
  void setDnsCallback(DnsCallback callback) { dns_callback_ = callback; }

  // Log engelleme olayı
  void logBlock(const std::string &domain, const std::string &app_package);

private:
  void monitorLoop();

  // Blocklist indirme ve parse
  std::unordered_set<std::string> downloadBlocklist(const std::string &url);
  std::unordered_set<std::string> parseHostsFile(const std::string &content);

  // Hosts dosyası işlemleri
  std::string readHostsFile();
  bool writeHostsFile(const std::string &content);
  bool backupHostsFile();
  std::string generateHostsContent();

  // DNS izleme (logcat üzerinden)
  void watchDnsQueries();

  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  std::thread dns_thread_;
  DnsCallback dns_callback_;

  // Engellenen domainler (bellekte)
  std::unordered_set<std::string> blocked_domains_;
  std::unordered_map<std::string, BlockCategory> domain_categories_;

  // Whitelist
  std::unordered_set<std::string> whitelist_;

  // Etkin kategoriler
  std::unordered_set<BlockCategory> enabled_categories_ = {
      BlockCategory::ADS, BlockCategory::ANALYTICS, BlockCategory::MALWARE};

  // Blocklist kaynakları
  std::vector<std::pair<std::string, BlockCategory>> blocklist_sources_ = {
      {"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
       BlockCategory::ADS},
      {"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts",
       BlockCategory::ADS},
      {"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/"
       "data/hosts/spy.txt",
       BlockCategory::ANALYTICS},
      {"https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/"
       "master/hosts",
       BlockCategory::MALWARE}};

  // İstatistikler
  BlockerStats stats_;
  std::vector<BlockedDomain> recent_blocks_;

  // Paths
  std::string hosts_path_ = "/system/etc/hosts";
  std::string backup_path_ = "/data/clara/hosts.backup";
  std::string cache_path_ = "/data/clara/cache/blocklists";

  int update_interval_hours_ = 24;
};

} // namespace clara

#endif // CLARA_TRACKER_BLOCKER_H
