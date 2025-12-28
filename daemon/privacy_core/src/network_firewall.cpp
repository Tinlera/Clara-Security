/**
 * CLARA Security - Network Firewall Implementation
 */

#include "../include/network_firewall.h"
#include <chrono>
#include <cstdio>
#include <fstream>
#include <regex>
#include <sstream>
#include <syslog.h>

namespace clara {

const std::string NetworkFirewall::CHAIN_NAME = "CLARA_FIREWALL";
const std::string NetworkFirewall::RULES_FILE =
    "/data/clara/config/firewall_rules.json";

NetworkFirewall::NetworkFirewall() : initialized_(false) {
  syslog(LOG_INFO, "NetworkFirewall oluşturuluyor...");
}

NetworkFirewall::~NetworkFirewall() {
  if (initialized_) {
    stop();
  }
}

std::string NetworkFirewall::executeCommand(const std::string &cmd) {
  std::string result;
  FILE *pipe = popen(cmd.c_str(), "r");
  if (pipe) {
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
      result += buffer;
    }
    pclose(pipe);
  }
  return result;
}

bool NetworkFirewall::executeiptables(const std::string &rule) {
  std::string cmd = "iptables " + rule + " 2>&1";
  std::string result = executeCommand(cmd);

  if (result.find("error") != std::string::npos ||
      result.find("Bad") != std::string::npos) {
    syslog(LOG_ERR, "iptables hatası: %s -> %s", rule.c_str(), result.c_str());
    return false;
  }

  return true;
}

bool NetworkFirewall::createChain() {
  // Zaten varsa başarılı say
  std::string check = executeCommand("iptables -L " + CHAIN_NAME + " 2>&1");
  if (check.find("No chain") == std::string::npos) {
    syslog(LOG_DEBUG, "CLARA_FIREWALL chain zaten mevcut");
    return true;
  }

  // Chain oluştur
  if (!executeiptables("-N " + CHAIN_NAME)) {
    return false;
  }

  // OUTPUT'a bağla
  if (!executeiptables("-A OUTPUT -j " + CHAIN_NAME)) {
    return false;
  }

  syslog(LOG_INFO, "CLARA_FIREWALL chain oluşturuldu");
  return true;
}

bool NetworkFirewall::deleteChain() {
  // OUTPUT'tan kaldır
  executeiptables("-D OUTPUT -j " + CHAIN_NAME);

  // Chain'i temizle
  executeiptables("-F " + CHAIN_NAME);

  // Chain'i sil
  executeiptables("-X " + CHAIN_NAME);

  syslog(LOG_INFO, "CLARA_FIREWALL chain silindi");
  return true;
}

bool NetworkFirewall::initialize() {
  syslog(LOG_INFO, "NetworkFirewall başlatılıyor...");

  // iptables chain oluştur
  if (!createChain()) {
    syslog(LOG_ERR, "iptables chain oluşturulamadı!");
    return false;
  }

  // Kuralları yükle
  loadRules();

  // Kuralları uygula
  applyAllRules();

  initialized_ = true;
  syslog(LOG_INFO, "NetworkFirewall başlatıldı (%zu kural)", rules_.size());
  return true;
}

void NetworkFirewall::stop() {
  if (!initialized_)
    return;

  // Kuralları kaydet
  saveRules();

  // Chain'i temizle (kuralları kaldır ama chain'i bırak)
  executeiptables("-F " + CHAIN_NAME);

  initialized_ = false;
  syslog(LOG_INFO, "NetworkFirewall durduruldu");
}

int NetworkFirewall::getUidByPackage(const std::string &package_name) {
  std::string cmd =
      "pm dump " + package_name + " 2>/dev/null | grep 'userId=' | head -1";
  std::string result = executeCommand(cmd);

  std::regex uid_regex("userId=(\\d+)");
  std::smatch match;

  if (std::regex_search(result, match, uid_regex)) {
    return std::stoi(match[1].str());
  }

  return -1;
}

std::string NetworkFirewall::getPackageByUid(int uid) {
  std::string cmd =
      "pm list packages -U 2>/dev/null | grep 'uid:" + std::to_string(uid) +
      "'";
  std::string result = executeCommand(cmd);

  std::regex pkg_regex("package:([^\\s]+)");
  std::smatch match;

  if (std::regex_search(result, match, pkg_regex)) {
    return match[1].str();
  }

  return "";
}

bool NetworkFirewall::setRule(const std::string &package_name,
                              FirewallAction wifi_action,
                              FirewallAction mobile_action) {
  int uid = getUidByPackage(package_name);
  if (uid < 0) {
    syslog(LOG_WARNING, "UID bulunamadı: %s", package_name.c_str());
    return false;
  }

  // Eski kuralı kaldır
  if (rules_.count(package_name) > 0) {
    removeIptablesRule(rules_[package_name]);
  }

  // Yeni kural oluştur
  FirewallRule rule;
  rule.package_name = package_name;
  rule.uid = uid;
  rule.wifi_action = wifi_action;
  rule.mobile_action = mobile_action;
  rule.is_system_app = (package_name.find("com.android.") == 0 ||
                        package_name.find("com.google.android.") == 0);
  rule.is_user_defined = true;
  rule.created_time = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
  rule.block_count = 0;
  rule.last_block_time = 0;

  // iptables'a uygula
  if (!applyRule(rule)) {
    return false;
  }

  // Kaydet
  rules_[package_name] = rule;
  stats_.total_rules = rules_.size();

  if (wifi_action == FirewallAction::DENY ||
      mobile_action == FirewallAction::DENY) {
    stats_.blocked_apps++;
  }

  if (callback_) {
    callback_(rule);
  }

  syslog(LOG_INFO,
         "Firewall kuralı eklendi: %s (UID: %d, WiFi: %d, Mobile: %d)",
         package_name.c_str(), uid, static_cast<int>(wifi_action),
         static_cast<int>(mobile_action));

  return true;
}

bool NetworkFirewall::applyRule(const FirewallRule &rule) {
  // WiFi kuralı (wlan0)
  if (rule.wifi_action == FirewallAction::DENY) {
    std::string cmd = "-A " + CHAIN_NAME + " -m owner --uid-owner " +
                      std::to_string(rule.uid) + " -o wlan0 -j DROP";
    executeiptables(cmd);
  }

  // Mobile kuralı (rmnet+, ccmni+, etc.)
  if (rule.mobile_action == FirewallAction::DENY) {
    std::string cmd = "-A " + CHAIN_NAME + " -m owner --uid-owner " +
                      std::to_string(rule.uid) + " ! -o wlan0 -j DROP";
    executeiptables(cmd);
  }

  // Karantina (tüm trafik engellenir)
  if (rule.wifi_action == FirewallAction::QUARANTINE ||
      rule.mobile_action == FirewallAction::QUARANTINE) {
    std::string cmd = "-A " + CHAIN_NAME + " -m owner --uid-owner " +
                      std::to_string(rule.uid) + " -j DROP";
    executeiptables(cmd);
  }

  return true;
}

bool NetworkFirewall::removeIptablesRule(const FirewallRule &rule) {
  // Tüm bu UID ile ilgili kuralları kaldır
  std::string uid_str = std::to_string(rule.uid);

  // -D ile sil (birkaç kez dene, birden fazla kural olabilir)
  for (int i = 0; i < 5; i++) {
    std::string cmd =
        "-D " + CHAIN_NAME + " -m owner --uid-owner " + uid_str + " -j DROP";
    std::string result = executeCommand("iptables " + cmd + " 2>&1");
    if (result.find("No chain") != std::string::npos ||
        result.find("Bad rule") != std::string::npos) {
      break;
    }
  }

  return true;
}

FirewallRule NetworkFirewall::getRule(const std::string &package_name) {
  if (rules_.count(package_name) > 0) {
    return rules_[package_name];
  }

  // Varsayılan kural (izin ver)
  FirewallRule default_rule;
  default_rule.package_name = package_name;
  default_rule.wifi_action = FirewallAction::ALLOW;
  default_rule.mobile_action = FirewallAction::ALLOW;
  default_rule.is_user_defined = false;

  return default_rule;
}

std::vector<FirewallRule> NetworkFirewall::getAllRules() {
  std::vector<FirewallRule> result;
  for (const auto &pair : rules_) {
    result.push_back(pair.second);
  }
  return result;
}

bool NetworkFirewall::removeRule(const std::string &package_name) {
  if (rules_.count(package_name) == 0) {
    return false;
  }

  removeIptablesRule(rules_[package_name]);
  rules_.erase(package_name);
  stats_.total_rules = rules_.size();

  syslog(LOG_INFO, "Firewall kuralı kaldırıldı: %s", package_name.c_str());
  return true;
}

void NetworkFirewall::clearAllRules() {
  executeiptables("-F " + CHAIN_NAME);
  rules_.clear();
  stats_.total_rules = 0;
  stats_.blocked_apps = 0;

  syslog(LOG_INFO, "Tüm firewall kuralları temizlendi");
}

bool NetworkFirewall::blockImmediately(const std::string &package_name) {
  return setRule(package_name, FirewallAction::DENY, FirewallAction::DENY);
}

bool NetworkFirewall::unblock(const std::string &package_name) {
  return removeRule(package_name);
}

bool NetworkFirewall::canAccess(const std::string &package_name,
                                NetworkType network) {
  if (rules_.count(package_name) == 0) {
    return true; // Varsayılan: izin ver
  }

  const FirewallRule &rule = rules_[package_name];

  switch (network) {
  case NetworkType::WIFI:
    return rule.wifi_action == FirewallAction::ALLOW;
  case NetworkType::MOBILE:
    return rule.mobile_action == FirewallAction::ALLOW;
  case NetworkType::ALL:
    return rule.wifi_action == FirewallAction::ALLOW &&
           rule.mobile_action == FirewallAction::ALLOW;
  default:
    return true;
  }
}

void NetworkFirewall::loadRules() {
  std::ifstream file(RULES_FILE);
  if (!file.is_open()) {
    syslog(LOG_DEBUG, "Firewall kuralları dosyası bulunamadı");
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#' || line[0] == '[')
      continue;

    // Basit format: package_name,wifi_action,mobile_action
    std::istringstream iss(line);
    std::string pkg, wifi_str, mobile_str;

    if (std::getline(iss, pkg, ',') && std::getline(iss, wifi_str, ',') &&
        std::getline(iss, mobile_str, ',')) {

      FirewallAction wifi_action =
          static_cast<FirewallAction>(std::stoi(wifi_str));
      FirewallAction mobile_action =
          static_cast<FirewallAction>(std::stoi(mobile_str));

      int uid = getUidByPackage(pkg);
      if (uid >= 0) {
        FirewallRule rule;
        rule.package_name = pkg;
        rule.uid = uid;
        rule.wifi_action = wifi_action;
        rule.mobile_action = mobile_action;
        rule.is_user_defined = true;

        rules_[pkg] = rule;
      }
    }
  }

  stats_.total_rules = rules_.size();
  syslog(LOG_INFO, "%zu firewall kuralı yüklendi", rules_.size());
}

void NetworkFirewall::saveRules() {
  std::ofstream file(RULES_FILE);
  if (!file.is_open()) {
    syslog(LOG_ERR, "Firewall kuralları kaydedilemedi: %s", RULES_FILE.c_str());
    return;
  }

  file << "# CLARA Network Firewall Rules\n";
  file << "# Format: package_name,wifi_action,mobile_action\n";
  file << "# Actions: 0=ALLOW, 1=DENY, 2=LOG_ONLY, 3=QUARANTINE\n\n";

  for (const auto &pair : rules_) {
    const FirewallRule &rule = pair.second;
    if (rule.is_user_defined) {
      file << rule.package_name << "," << static_cast<int>(rule.wifi_action)
           << "," << static_cast<int>(rule.mobile_action) << "\n";
    }
  }

  syslog(LOG_INFO, "Firewall kuralları kaydedildi");
}

void NetworkFirewall::applyAllRules() {
  for (const auto &pair : rules_) {
    applyRule(pair.second);
  }
  syslog(LOG_INFO, "%zu firewall kuralı uygulandı", rules_.size());
}

std::vector<AppNetworkStats> NetworkFirewall::getNetworkStats() {
  std::vector<AppNetworkStats> stats_list;

  // /proc/net/xt_qtaguid/stats'dan oku
  std::ifstream file("/proc/net/xt_qtaguid/stats");
  if (!file.is_open()) {
    // Alternatif: TrafficStats API simülasyonu
    return stats_list;
  }

  std::string line;
  std::unordered_map<int, AppNetworkStats> uid_stats;

  while (std::getline(file, line)) {
    std::istringstream iss(line);
    int idx, uid_tag, counter_set, uid;
    int64_t rx_bytes, rx_packets, tx_bytes, tx_packets;
    std::string iface;

    if (iss >> idx >> iface >> uid_tag >> counter_set >> uid >> rx_bytes >>
        rx_packets >> tx_bytes >> tx_packets) {

      if (uid < 10000)
        continue; // Sistem UID'lerini atla

      if (uid_stats.count(uid) == 0) {
        AppNetworkStats s;
        s.uid = uid;
        s.package_name = getPackageByUid(uid);
        uid_stats[uid] = s;
      }

      if (iface.find("wlan") != std::string::npos) {
        uid_stats[uid].wifi_rx_bytes += rx_bytes;
        uid_stats[uid].wifi_tx_bytes += tx_bytes;
      } else {
        uid_stats[uid].mobile_rx_bytes += rx_bytes;
        uid_stats[uid].mobile_tx_bytes += tx_bytes;
      }
    }
  }

  for (const auto &pair : uid_stats) {
    stats_list.push_back(pair.second);
  }

  return stats_list;
}

AppNetworkStats NetworkFirewall::getAppStats(const std::string &package_name) {
  int uid = getUidByPackage(package_name);

  auto all_stats = getNetworkStats();
  for (const auto &s : all_stats) {
    if (s.uid == uid) {
      return s;
    }
  }

  AppNetworkStats empty;
  empty.package_name = package_name;
  return empty;
}

NetworkFirewall::Stats NetworkFirewall::getStats() const { return stats_; }

void NetworkFirewall::setRuleChangeCallback(RuleChangeCallback callback) {
  callback_ = callback;
}

} // namespace clara
