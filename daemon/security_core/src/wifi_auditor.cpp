/**
 * CLARA Security - WiFi Security Auditor Implementation
 */

#include "../include/wifi_auditor.h"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <regex>
#include <sstream>
#include <syslog.h>
#include <thread>
#include <unistd.h>

namespace clara {

// Güvenilir DNS sunucuları
const std::vector<std::string> WifiAuditor::TRUSTED_DNS = {
    "8.8.8.8",         // Google
    "8.8.4.4",         // Google
    "1.1.1.1",         // Cloudflare
    "1.0.0.1",         // Cloudflare
    "9.9.9.9",         // Quad9
    "149.112.112.112", // Quad9
    "208.67.222.222",  // OpenDNS
    "208.67.220.220",  // OpenDNS
};

WifiAuditor::WifiAuditor() : running_(false) {
  syslog(LOG_INFO, "WifiAuditor oluşturuluyor...");
}

WifiAuditor::~WifiAuditor() { stopMonitoring(); }

std::string WifiAuditor::executeCommand(const std::string &cmd) {
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

bool WifiAuditor::initialize() {
  syslog(LOG_INFO, "WifiAuditor başlatılıyor...");

  // Mevcut gateway ve DNS'i kaydet
  auto gateway = getGateway();
  known_gateway_ip_ = gateway.first;
  known_gateway_mac_ = gateway.second;

  known_dns_servers_ = getDnsServers();

  syslog(LOG_INFO, "Gateway: %s (%s)", known_gateway_ip_.c_str(),
         known_gateway_mac_.c_str());

  return true;
}

WifiNetworkInfo WifiAuditor::getConnectedNetwork() {
  WifiNetworkInfo info;

  // dumpsys wifi ile bağlı ağ bilgisini al
  std::string result =
      executeCommand("dumpsys wifi 2>/dev/null | grep -A20 'mWifiInfo'");

  // SSID
  std::regex ssid_regex("SSID: \"?([^\"\\s,]+)\"?");
  std::smatch match;
  if (std::regex_search(result, match, ssid_regex)) {
    info.ssid = match[1].str();
  }

  // BSSID
  std::regex bssid_regex("BSSID: ([0-9a-fA-F:]+)");
  if (std::regex_search(result, match, bssid_regex)) {
    info.bssid = match[1].str();
  }

  // Frekans
  std::regex freq_regex("Frequency: (\\d+)");
  if (std::regex_search(result, match, freq_regex)) {
    info.frequency = std::stoi(match[1].str());
  }

  // Sinyal seviyesi
  std::regex rssi_regex("RSSI: (-?\\d+)");
  if (std::regex_search(result, match, rssi_regex)) {
    info.signal_level = std::stoi(match[1].str());
  }

  // Güvenlik bilgisi
  std::string sec_result = executeCommand(
      "dumpsys wifi 2>/dev/null | grep -i 'security\\|capabilities' | head -5");

  if (sec_result.find("WPA3") != std::string::npos) {
    info.security = WifiSecurityLevel::WPA3;
    info.security_string = "WPA3";
  } else if (sec_result.find("WPA2-EAP") != std::string::npos ||
             sec_result.find("802.1X") != std::string::npos) {
    info.security = WifiSecurityLevel::WPA2_ENTERPRISE;
    info.security_string = "WPA2-Enterprise";
  } else if (sec_result.find("WPA2") != std::string::npos) {
    info.security = WifiSecurityLevel::WPA2_PSK;
    info.security_string = "WPA2-PSK";
  } else if (sec_result.find("WPA") != std::string::npos) {
    info.security = WifiSecurityLevel::WPA;
    info.security_string = "WPA";
  } else if (sec_result.find("WEP") != std::string::npos) {
    info.security = WifiSecurityLevel::WEP;
    info.security_string = "WEP";
  } else if (sec_result.find("OPEN") != std::string::npos ||
             sec_result.find("[ESS]") != std::string::npos) {
    info.security = WifiSecurityLevel::OPEN;
    info.security_string = "Open";
  } else {
    info.security = WifiSecurityLevel::UNKNOWN;
    info.security_string = "Unknown";
  }

  info.is_connected = !info.ssid.empty();

  return info;
}

std::vector<WifiNetworkInfo> WifiAuditor::scanNearbyNetworks() {
  std::vector<WifiNetworkInfo> networks;

  // WiFi tarama başlat
  executeCommand("cmd wifi start-scan 2>/dev/null");
  usleep(500000); // 500ms bekle

  // Tarama sonuçlarını al
  std::string result = executeCommand("cmd wifi list-scan-results 2>/dev/null");

  std::istringstream stream(result);
  std::string line;

  while (std::getline(stream, line)) {
    if (line.empty() || line.find("BSSID") != std::string::npos)
      continue;

    // Format: BSSID FREQ RSSI CAPS SSID
    std::istringstream iss(line);
    WifiNetworkInfo info;
    std::string caps, ssid_part;

    if (iss >> info.bssid >> info.frequency >> info.signal_level >> caps) {
      // SSID'yi al (geri kalan her şey)
      std::getline(iss >> std::ws, info.ssid);
      info.security_string = caps;
      info.security = parseSecurityType(caps);
      info.is_connected = false;

      networks.push_back(info);
    }
  }

  return networks;
}

WifiSecurityLevel
WifiAuditor::parseSecurityType(const std::string &security_str) {
  std::string upper = security_str;
  std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

  if (upper.find("WPA3") != std::string::npos)
    return WifiSecurityLevel::WPA3;
  if (upper.find("WPA2-EAP") != std::string::npos ||
      upper.find("EAP") != std::string::npos)
    return WifiSecurityLevel::WPA2_ENTERPRISE;
  if (upper.find("WPA2") != std::string::npos)
    return WifiSecurityLevel::WPA2_PSK;
  if (upper.find("WPA") != std::string::npos)
    return WifiSecurityLevel::WPA;
  if (upper.find("WEP") != std::string::npos)
    return WifiSecurityLevel::WEP;
  if (upper.find("ESS") != std::string::npos &&
      upper.find("WPA") == std::string::npos)
    return WifiSecurityLevel::OPEN;

  return WifiSecurityLevel::UNKNOWN;
}

WifiAuditResult WifiAuditor::performAudit() {
  WifiAuditResult result;
  result.network = getConnectedNetwork();
  result.audit_time = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

  syslog(LOG_INFO, "WiFi audit başlatıldı: %s", result.network.ssid.c_str());

  // 1. Şifreleme kontrolü
  switch (result.network.security) {
  case WifiSecurityLevel::OPEN:
    result.threats.push_back(WifiThreatType::OPEN_NETWORK);
    result.warnings.push_back(
        "⚠️ AÇIK AĞ: Bu ağ şifreleme kullanmıyor! Tüm trafiğiniz görülebilir.");
    result.recommendations.push_back(
        "VPN kullanın veya şifreli bir ağa bağlanın.");
    break;

  case WifiSecurityLevel::WEP:
    result.threats.push_back(WifiThreatType::WEAK_ENCRYPTION);
    result.warnings.push_back(
        "⚠️ WEP şifreleme çok zayıf ve dakikalar içinde kırılabilir.");
    result.recommendations.push_back(
        "Mümkünse WPA2 veya WPA3 kullanan bir ağa bağlanın.");
    break;

  case WifiSecurityLevel::WPA:
    result.warnings.push_back("WPA şifreleme artık güvenli kabul edilmiyor.");
    result.recommendations.push_back(
        "Router'ınızı WPA2 veya WPA3'e yükseltin.");
    break;

  case WifiSecurityLevel::WPA2_PSK:
    // İyi, ama ek kontroller yap
    break;

  case WifiSecurityLevel::WPA2_ENTERPRISE:
  case WifiSecurityLevel::WPA3:
    // En güvenli
    break;

  default:
    result.warnings.push_back("Şifreleme türü tespit edilemedi.");
    break;
  }

  // 2. Evil Twin kontrolü
  if (checkEvilTwin()) {
    result.threats.push_back(WifiThreatType::EVIL_TWIN);
    result.warnings.push_back("🚨 UYARI: Aynı isimde birden fazla ağ tespit "
                              "edildi! Sahte AP olabilir.");
    result.recommendations.push_back(
        "Bağlı olduğunuz ağın MAC adresini doğrulayın.");
  }

  // 3. DNS hijacking kontrolü
  if (checkDnsHijacking()) {
    result.threats.push_back(WifiThreatType::DNS_HIJACK);
    result.warnings.push_back(
        "🚨 DNS sunucuları değiştirilmiş olabilir! Saldırı riski.");
    result.recommendations.push_back(
        "Manuel olarak güvenilir DNS ayarlayın (1.1.1.1 veya 8.8.8.8).");
  }

  // 4. ARP spoofing kontrolü
  if (checkArpSpoofing()) {
    result.threats.push_back(WifiThreatType::ARP_SPOOFING);
    result.warnings.push_back(
        "🚨 ARP tablosunda şüpheli girişler tespit edildi!");
    result.recommendations.push_back(
        "Bu ağdan ayrılın ve güvenlik uzmanına danışın.");
  }

  // 5. Güvenlik skoru hesapla
  result.security_score = calculateSecurityScore(result.network);

  // Ek öneriler
  if (result.security_score < 50) {
    result.recommendations.push_back(
        "VPN kullanmanızı şiddetle tavsiye ederiz.");
    result.recommendations.push_back(
        "Online bankacılık ve hassas işlemlerden kaçının.");
  }

  syslog(LOG_INFO, "WiFi audit tamamlandı: Skor=%d, Tehdit=%zu",
         result.security_score, result.threats.size());

  return result;
}

int WifiAuditor::quickSecurityCheck() {
  auto network = getConnectedNetwork();
  return calculateSecurityScore(network);
}

int WifiAuditor::calculateSecurityScore(const WifiNetworkInfo &network) {
  int score = 100;

  // Şifreleme puanı
  switch (network.security) {
  case WifiSecurityLevel::OPEN:
    score -= 70;
    break;
  case WifiSecurityLevel::WEP:
    score -= 50;
    break;
  case WifiSecurityLevel::WPA:
    score -= 30;
    break;
  case WifiSecurityLevel::WPA2_PSK:
    score -= 10;
    break;
  case WifiSecurityLevel::WPA2_ENTERPRISE:
    score -= 5;
    break;
  case WifiSecurityLevel::WPA3:
    // Tam puan
    break;
  default:
    score -= 20;
    break;
  }

  // Sinyal kalitesi bonus/ceza
  if (network.signal_level < -80) {
    score -= 5; // Çok zayıf sinyal, man-in-the-middle riski
  }

  // Evil twin kontrolü
  if (checkEvilTwin()) {
    score -= 30;
  }

  // DNS kontrolü
  if (checkDnsHijacking()) {
    score -= 25;
  }

  // ARP kontrolü
  if (checkArpSpoofing()) {
    score -= 35;
  }

  return std::max(0, std::min(100, score));
}

bool WifiAuditor::checkEvilTwin() {
  auto connected = getConnectedNetwork();
  auto nearby = scanNearbyNetworks();

  int same_ssid_count = 0;
  for (const auto &net : nearby) {
    if (net.ssid == connected.ssid && net.bssid != connected.bssid) {
      same_ssid_count++;
      syslog(LOG_WARNING, "Aynı SSID farklı BSSID: %s (%s vs %s)",
             net.ssid.c_str(), net.bssid.c_str(), connected.bssid.c_str());
    }
  }

  return same_ssid_count > 0;
}

bool WifiAuditor::checkDnsHijacking() {
  auto current_dns = getDnsServers();

  // Bilinen DNS ile karşılaştır
  for (const auto &dns : current_dns) {
    // Güvenilir DNS listesinde mi?
    bool is_trusted = std::find(TRUSTED_DNS.begin(), TRUSTED_DNS.end(), dns) !=
                      TRUSTED_DNS.end();

    // Gateway ile aynı subnet'te mi? (yerel DNS normal olabilir)
    bool is_local = (dns.find("192.168.") == 0 || dns.find("10.") == 0 ||
                     dns.find("172.") == 0);

    if (!is_trusted && !is_local) {
      // Şüpheli DNS
      syslog(LOG_WARNING, "Bilinmeyen DNS sunucusu: %s", dns.c_str());

      // Önceki DNS'lerden farklı mı?
      if (std::find(known_dns_servers_.begin(), known_dns_servers_.end(),
                    dns) == known_dns_servers_.end()) {
        return true; // DNS değişmiş!
      }
    }
  }

  return false;
}

bool WifiAuditor::checkArpSpoofing() {
  auto arp_table = getArpTable();
  auto gateway = getGateway();

  // Aynı IP'ye birden fazla MAC?
  std::unordered_map<std::string, std::string> ip_to_mac;

  for (const auto &entry : arp_table) {
    if (ip_to_mac.count(entry.ip_address) > 0) {
      if (ip_to_mac[entry.ip_address] != entry.mac_address) {
        syslog(LOG_ALERT, "ARP çakışma! IP: %s, MAC1: %s, MAC2: %s",
               entry.ip_address.c_str(), ip_to_mac[entry.ip_address].c_str(),
               entry.mac_address.c_str());
        return true;
      }
    }
    ip_to_mac[entry.ip_address] = entry.mac_address;
  }

  // Gateway MAC değişti mi?
  if (!known_gateway_mac_.empty() && !gateway.second.empty()) {
    if (gateway.second != known_gateway_mac_) {
      syslog(LOG_ALERT, "Gateway MAC değişti! Eski: %s, Yeni: %s",
             known_gateway_mac_.c_str(), gateway.second.c_str());
      return true;
    }
  }

  return false;
}

bool WifiAuditor::monitorGatewayMac() {
  auto gateway = getGateway();

  if (known_gateway_mac_.empty()) {
    known_gateway_mac_ = gateway.second;
    known_gateway_ip_ = gateway.first;
    return true;
  }

  if (gateway.second != known_gateway_mac_) {
    syslog(LOG_ALERT, "Gateway MAC değişti!");

    if (threat_callback_) {
      threat_callback_(WifiThreatType::ARP_SPOOFING,
                       "Gateway MAC adresi değişti: " + gateway.second);
    }

    return false;
  }

  return true;
}

std::vector<ArpEntry> WifiAuditor::getArpTable() {
  std::vector<ArpEntry> entries;

  std::ifstream file("/proc/net/arp");
  std::string line;

  // Başlık satırını atla
  std::getline(file, line);

  while (std::getline(file, line)) {
    std::istringstream iss(line);
    ArpEntry entry;
    std::string hw_type, flags, hw_addr;

    if (iss >> entry.ip_address >> hw_type >> flags >> entry.mac_address >>
        hw_addr >> entry.interface) {

      if (entry.mac_address != "00:00:00:00:00:00") {
        entries.push_back(entry);
      }
    }
  }

  return entries;
}

std::vector<std::string> WifiAuditor::getDnsServers() {
  std::vector<std::string> servers;

  // getprop ile DNS al
  std::string result = executeCommand("getprop net.dns1 2>/dev/null");
  if (!result.empty()) {
    result.erase(result.find_last_not_of(" \t\n\r") + 1);
    if (!result.empty())
      servers.push_back(result);
  }

  result = executeCommand("getprop net.dns2 2>/dev/null");
  if (!result.empty()) {
    result.erase(result.find_last_not_of(" \t\n\r") + 1);
    if (!result.empty())
      servers.push_back(result);
  }

  return servers;
}

std::pair<std::string, std::string> WifiAuditor::getGateway() {
  std::string ip, mac;

  // Gateway IP
  std::string result =
      executeCommand("ip route | grep default | awk '{print $3}' | head -1");
  result.erase(result.find_last_not_of(" \t\n\r") + 1);
  ip = result;

  // Gateway MAC (ARP tablosundan)
  if (!ip.empty()) {
    auto arp_table = getArpTable();
    for (const auto &entry : arp_table) {
      if (entry.ip_address == ip) {
        mac = entry.mac_address;
        break;
      }
    }
  }

  return {ip, mac};
}

void WifiAuditor::setThreatCallback(ThreatCallback callback) {
  threat_callback_ = callback;
}

void WifiAuditor::startMonitoring(int interval_seconds) {
  if (running_)
    return;

  running_ = true;
  monitor_thread_ =
      std::thread(&WifiAuditor::monitorLoop, this, interval_seconds);
  syslog(LOG_INFO, "WiFi izleme başlatıldı (interval: %ds)", interval_seconds);
}

void WifiAuditor::stopMonitoring() {
  running_ = false;
  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }
  syslog(LOG_INFO, "WiFi izleme durduruldu");
}

void WifiAuditor::monitorLoop(int interval_seconds) {
  while (running_) {
    // Gateway MAC kontrolü
    if (!monitorGatewayMac()) {
      if (threat_callback_) {
        threat_callback_(WifiThreatType::ARP_SPOOFING, "Gateway MAC değişti!");
      }
    }

    // DNS kontrolü
    auto current_dns = getDnsServers();
    if (current_dns != known_dns_servers_) {
      syslog(LOG_WARNING, "DNS sunucuları değişti!");
      if (threat_callback_) {
        threat_callback_(WifiThreatType::DNS_HIJACK, "DNS sunucuları değişti!");
      }
      known_dns_servers_ = current_dns;
    }

    std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
  }
}

} // namespace clara
