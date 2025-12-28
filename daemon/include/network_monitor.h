/**
 * CLARA Security - Network Monitor Module
 * Ağ trafiği analizi ve anomali tespiti
 */

#ifndef CLARA_NETWORK_MONITOR_H
#define CLARA_NETWORK_MONITOR_H

#include "clara_daemon.h"
#include <netinet/in.h>
#include <unordered_set>

namespace clara {

/**
 * Ağ izleme modülü
 * /proc/net parsing ve eBPF (ileride)
 */
class NetworkMonitor : public IModule {
public:
  NetworkMonitor();
  ~NetworkMonitor() override;

  // IModule implementasyonu
  const std::string &getName() const override { return name_; }
  bool initialize() override;
  void start() override;
  void stop() override;
  bool isRunning() const override { return running_.load(); }
  void setEventCallback(EventCallback callback) override {
    callback_ = callback;
  }

  // Ağ analizi
  std::vector<NetworkFlow> getCurrentConnections();
  ThreatInfo analyzeConnection(const NetworkFlow &flow);

  // DNS izleme
  void logDnsQuery(const std::string &domain, const std::string &resolved_ip);
  bool isBlockedDomain(const std::string &domain);

  // Anomali tespiti
  float calculateAnomalyScore(const NetworkFlow &flow);

  // İstatistikler
  uint64_t getTotalBytesSent() const { return total_bytes_sent_.load(); }
  uint64_t getTotalBytesReceived() const {
    return total_bytes_received_.load();
  }
  int getBlockedConnections() const { return blocked_connections_.load(); }

private:
  void monitorLoop();
  std::vector<NetworkFlow> parseProcNet(const std::string &proto);
  std::string resolveUid(int uid);
  void updateBlocklist();

  std::string name_ = "network_monitor";
  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  EventCallback callback_;

  // Blocklist
  std::unordered_set<std::string> blocked_domains_;
  std::unordered_set<std::string> blocked_ips_;

  // DNS cache
  std::unordered_map<std::string, std::vector<std::string>> dns_cache_;

  // Flow history (anomali tespiti için)
  std::vector<NetworkFlow> flow_history_;
  [[maybe_unused]] size_t max_history_size_ = 1000;

  // İstatistikler
  std::atomic<uint64_t> total_bytes_sent_{0};
  std::atomic<uint64_t> total_bytes_received_{0};
  std::atomic<int> blocked_connections_{0};

  // Ayarlar
  int check_interval_ms_ = 2000;
  bool dns_logging_ = true;
  [[maybe_unused]] bool anomaly_detection_ = true;
};

} // namespace clara

#endif // CLARA_NETWORK_MONITOR_H
