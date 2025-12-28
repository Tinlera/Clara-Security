/**
 * CLARA Security - Network Monitor Implementation
 */

#include "../include/network_monitor.h"
#include <algorithm>
#include <arpa/inet.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <syslog.h>
#include <unistd.h>

namespace clara {

NetworkMonitor::NetworkMonitor() {
  // Bilinen kötü domain'ler
  blocked_domains_ = {"malware.com", "phishing.example.com"};

  // Bilinen kötü IP'ler
  blocked_ips_ = {
      "0.0.0.0" // placeholder
  };
}

NetworkMonitor::~NetworkMonitor() { stop(); }

bool NetworkMonitor::initialize() {
  syslog(LOG_INFO, "Network Monitor başlatılıyor...");

  // /proc/net erişim kontrolü
  if (access("/proc/net/tcp", R_OK) != 0) {
    syslog(LOG_ERR, "/proc/net/tcp erişilemez");
    return false;
  }

  return true;
}

void NetworkMonitor::start() {
  if (running_.load())
    return;

  running_ = true;
  monitor_thread_ = std::thread(&NetworkMonitor::monitorLoop, this);
  syslog(LOG_INFO, "Network Monitor başlatıldı");
}

void NetworkMonitor::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  syslog(LOG_INFO, "Network Monitor durduruldu");
}

void NetworkMonitor::monitorLoop() {
  while (running_.load()) {
    try {
      auto connections = getCurrentConnections();

      for (const auto &conn : connections) {
        // Anomali analizi
        ThreatInfo threat = analyzeConnection(conn);

        if (threat.level >= ThreatLevel::MEDIUM) {
          SecurityEvent event;
          event.id =
              std::chrono::system_clock::now().time_since_epoch().count();
          event.timestamp = event.id;
          event.type = EventType::NETWORK_ANOMALY;
          event.level = threat.level;
          event.source =
              conn.remote_addr + ":" + std::to_string(conn.remote_port);
          event.description = threat.description;
          event.handled = false;

          if (callback_) {
            callback_(event);
          }
        }

        // İstatistikleri güncelle
        total_bytes_sent_ += conn.bytes_sent;
        total_bytes_received_ += conn.bytes_received;
      }

    } catch (const std::exception &e) {
      syslog(LOG_ERR, "Network Monitor hata: %s", e.what());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(check_interval_ms_));
  }
}

std::vector<NetworkFlow> NetworkMonitor::getCurrentConnections() {
  std::vector<NetworkFlow> connections;

  // TCP bağlantılarını oku
  auto tcp4 = parseProcNet("/proc/net/tcp");
  auto tcp6 = parseProcNet("/proc/net/tcp6");

  connections.insert(connections.end(), tcp4.begin(), tcp4.end());
  connections.insert(connections.end(), tcp6.begin(), tcp6.end());

  // UDP'yi de ekle
  auto udp4 = parseProcNet("/proc/net/udp");
  connections.insert(connections.end(), udp4.begin(), udp4.end());

  return connections;
}

std::vector<NetworkFlow> NetworkMonitor::parseProcNet(const std::string &path) {
  std::vector<NetworkFlow> flows;

  std::ifstream file(path);
  if (!file.is_open()) {
    return flows;
  }

  std::string line;
  // İlk satırı atla (header)
  std::getline(file, line);

  while (std::getline(file, line)) {
    std::istringstream iss(line);
    std::string sl, local_address, remote_address, st;
    int tx_queue, rx_queue, tr, tm_when, retrnsmt, uid;

    // Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when
    // retrnsmt uid ...
    iss >> sl >> local_address >> remote_address >> st >> std::hex >>
        tx_queue >> rx_queue >> tr >> tm_when >> retrnsmt >> std::dec >> uid;

    NetworkFlow flow;

    // Local address parse (IP:PORT hex formatında)
    size_t colon_pos = local_address.find(':');
    if (colon_pos != std::string::npos) {
      std::string ip_hex = local_address.substr(0, colon_pos);
      std::string port_hex = local_address.substr(colon_pos + 1);

      // Hex IP to string
      unsigned int ip_int = std::stoul(ip_hex, nullptr, 16);
      struct in_addr addr;
      addr.s_addr = ip_int;
      flow.local_addr = inet_ntoa(addr);
      flow.local_port = std::stoul(port_hex, nullptr, 16);
    }

    // Remote address parse
    colon_pos = remote_address.find(':');
    if (colon_pos != std::string::npos) {
      std::string ip_hex = remote_address.substr(0, colon_pos);
      std::string port_hex = remote_address.substr(colon_pos + 1);

      unsigned int ip_int = std::stoul(ip_hex, nullptr, 16);
      struct in_addr addr;
      addr.s_addr = ip_int;
      flow.remote_addr = inet_ntoa(addr);
      flow.remote_port = std::stoul(port_hex, nullptr, 16);
    }

    flow.uid = uid;
    flow.protocol = (path.find("tcp") != std::string::npos) ? "TCP" : "UDP";
    flow.app_name = resolveUid(uid);

    // tx/rx queue'u bytes olarak yaklaşık al
    flow.bytes_sent = tx_queue;
    flow.bytes_received = rx_queue;

    flows.push_back(flow);
  }

  return flows;
}

std::string NetworkMonitor::resolveUid(int uid) {
  // /data/system/packages.xml veya pm list ile UID'yi paket adına çevir
  // Basit implementasyon

  if (uid == 0)
    return "root";
  if (uid == 1000)
    return "system";
  if (uid < 10000)
    return "system";

  // Android uygulamaları 10000+ UID kullanır
  std::string packages_path = "/data/system/packages.list";
  std::ifstream file(packages_path);
  if (!file.is_open()) {
    return "uid:" + std::to_string(uid);
  }

  std::string line;
  while (std::getline(file, line)) {
    std::istringstream iss(line);
    std::string package;
    int app_uid;

    iss >> package >> app_uid;
    if (app_uid == uid) {
      return package;
    }
  }

  return "uid:" + std::to_string(uid);
}

ThreatInfo NetworkMonitor::analyzeConnection(const NetworkFlow &flow) {
  ThreatInfo threat;
  threat.source = flow.remote_addr + ":" + std::to_string(flow.remote_port);

  float risk_score = calculateAnomalyScore(flow);
  threat.confidence = risk_score;

  // Engellenen domain/IP kontrolü
  if (isBlockedDomain(flow.remote_addr)) {
    threat.level = ThreatLevel::HIGH;
    threat.type = "blocked_connection";
    threat.description = "Engellenen adrese bağlantı: " + flow.remote_addr;
    threat.recommended_actions = {ActionType::BLOCK, ActionType::NOTIFY};
    return threat;
  }

  // Risk seviyesi belirleme
  if (risk_score >= 0.8f) {
    threat.level = ThreatLevel::HIGH;
    threat.type = "network_anomaly";
    threat.description = "Anormal ağ aktivitesi";
  } else if (risk_score >= 0.5f) {
    threat.level = ThreatLevel::MEDIUM;
    threat.type = "suspicious_connection";
    threat.description = "Şüpheli bağlantı";
  } else if (risk_score >= 0.3f) {
    threat.level = ThreatLevel::LOW;
    threat.type = "unusual_traffic";
    threat.description = "Olağandışı trafik";
  } else {
    threat.level = ThreatLevel::NONE;
    threat.type = "normal";
    threat.description = "Normal bağlantı";
  }

  return threat;
}

float NetworkMonitor::calculateAnomalyScore(const NetworkFlow &flow) {
  float score = 0.0f;

  // 1. Suspicious ports
  std::vector<uint16_t> bad_ports = {4444,  5555, 6666, 6667, 31337,
                                     12345, 23,   445,  1433, 3389};

  for (uint16_t port : bad_ports) {
    if (flow.remote_port == port) {
      score += 0.4f;
      break;
    }
  }

  // 2. Unusual high ports
  if (flow.remote_port > 49152) {
    score += 0.1f;
  }

  // 3. Data exfiltration check (more sent than received)
  if (flow.bytes_sent > flow.bytes_received * 5 && flow.bytes_sent > 10000) {
    score += 0.3f;
  }

  // 4. Unknown app making connections
  if (flow.app_name.find("uid:") != std::string::npos) {
    score += 0.1f; // Couldn't resolve app name
  }

  return std::min(1.0f, score);
}

bool NetworkMonitor::isBlockedDomain(const std::string &domain) {
  // Domain veya IP engelli listede mi?
  if (blocked_domains_.count(domain) > 0) {
    return true;
  }

  if (blocked_ips_.count(domain) > 0) {
    return true;
  }

  return false;
}

void NetworkMonitor::logDnsQuery(const std::string &domain,
                                 const std::string &resolved_ip) {
  if (!dns_logging_)
    return;

  dns_cache_[domain].push_back(resolved_ip);

  // Cache boyutunu kontrol et
  if (dns_cache_[domain].size() > 10) {
    dns_cache_[domain].erase(dns_cache_[domain].begin());
  }

  // Engellenen domain kontrolü
  if (isBlockedDomain(domain)) {
    SecurityEvent event;
    event.id = std::chrono::system_clock::now().time_since_epoch().count();
    event.timestamp = event.id;
    event.type = EventType::NETWORK_ANOMALY;
    event.level = ThreatLevel::HIGH;
    event.source = domain;
    event.description = "Engellenen domain sorgulandı: " + domain;
    event.handled = false;

    if (callback_) {
      callback_(event);
    }

    blocked_connections_++;
  }
}

void NetworkMonitor::updateBlocklist() {
  // TODO: Remote blocklist'i indir ve güncelle
  syslog(LOG_INFO, "Blocklist güncelleniyor...");
}

} // namespace clara
