/**
 * CLARA Security - WiFi Security Auditor
 *
 * Bağlı WiFi ağının güvenlik analizini yapar:
 * - Şifreleme tipi kontrolü
 * - Bilinen zayıf şifre kalıpları
 * - Rogue AP tespiti
 * - DNS hijacking kontrolü
 * - ARP spoofing tespiti
 */

#ifndef CLARA_WIFI_AUDITOR_H
#define CLARA_WIFI_AUDITOR_H

#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace clara {

/**
 * WiFi güvenlik seviyesi
 */
enum class WifiSecurityLevel {
  UNKNOWN,
  OPEN,            // Şifresiz (çok tehlikeli)
  WEP,             // WEP (kırılması kolay)
  WPA,             // WPA (zayıf)
  WPA2_PSK,        // WPA2 Personal (iyi)
  WPA2_ENTERPRISE, // WPA2 Enterprise (çok iyi)
  WPA3,            // WPA3 (en iyi)
};

/**
 * Tehdit tipi
 */
enum class WifiThreatType {
  NONE,
  WEAK_ENCRYPTION, // Zayıf şifreleme
  OPEN_NETWORK,    // Açık ağ
  EVIL_TWIN,       // Sahte AP (aynı SSID)
  ROGUE_AP,        // Yetkisiz AP
  DNS_HIJACK,      // DNS yönlendirme
  ARP_SPOOFING,    // ARP zehirleme
  SSL_STRIP,       // SSL soyma girişimi
  CAPTIVE_PORTAL,  // Captive portal (dikkatli ol)
};

/**
 * WiFi ağ bilgisi
 */
struct WifiNetworkInfo {
  std::string ssid;
  std::string bssid; // MAC adresi
  int frequency;     // MHz
  int signal_level;  // dBm
  WifiSecurityLevel security;
  std::string security_string; // "WPA2-PSK" gibi
  bool is_connected;
  bool is_saved;
  bool is_hidden;
};

/**
 * Audit sonucu
 */
struct WifiAuditResult {
  WifiNetworkInfo network;
  int security_score; // 0-100
  std::vector<WifiThreatType> threats;
  std::vector<std::string> warnings;
  std::vector<std::string> recommendations;
  int64_t audit_time;
};

/**
 * ARP tablosu girişi
 */
struct ArpEntry {
  std::string ip_address;
  std::string mac_address;
  std::string interface;
};

/**
 * WiFi Security Auditor sınıfı
 */
class WifiAuditor {
public:
  WifiAuditor();
  ~WifiAuditor();

  /**
   * Auditor'ı başlat
   */
  bool initialize();

  /**
   * Tam güvenlik auditi yap
   */
  WifiAuditResult performAudit();

  /**
   * Hızlı güvenlik kontrolü
   */
  int quickSecurityCheck();

  /**
   * Bağlı ağ bilgisini al
   */
  WifiNetworkInfo getConnectedNetwork();

  /**
   * Çevredeki ağları tara
   */
  std::vector<WifiNetworkInfo> scanNearbyNetworks();

  /**
   * Evil Twin (sahte AP) kontrolü
   */
  bool checkEvilTwin();

  /**
   * DNS hijacking kontrolü
   */
  bool checkDnsHijacking();

  /**
   * ARP spoofing kontrolü
   */
  bool checkArpSpoofing();

  /**
   * Gateway MAC değişikliği izle
   */
  bool monitorGatewayMac();

  /**
   * Sürekli izleme başlat
   */
  void startMonitoring(int interval_seconds = 60);

  /**
   * İzlemeyi durdur
   */
  void stopMonitoring();

  /**
   * Tehdit callback'i
   */
  using ThreatCallback =
      std::function<void(WifiThreatType, const std::string &)>;
  void setThreatCallback(ThreatCallback callback);

  /**
   * ARP tablosunu al
   */
  std::vector<ArpEntry> getArpTable();

  /**
   * DNS sunucularını al
   */
  std::vector<std::string> getDnsServers();

  /**
   * Gateway IP ve MAC
   */
  std::pair<std::string, std::string> getGateway();

  /**
   * Güvenlik skoru hesapla
   */
  int calculateSecurityScore(const WifiNetworkInfo &network);

private:
  bool running_;
  std::thread monitor_thread_;
  ThreatCallback threat_callback_;

  // Bilinen gateway MAC adresi (değişiklik tespiti için)
  std::string known_gateway_mac_;
  std::string known_gateway_ip_;

  // Bilinen DNS'ler
  std::vector<std::string> known_dns_servers_;

  // Güvenilir DNS sunucuları
  static const std::vector<std::string> TRUSTED_DNS;

  // Yardımcı fonksiyonlar
  std::string executeCommand(const std::string &cmd);
  WifiSecurityLevel parseSecurityType(const std::string &security_str);
  void monitorLoop(int interval_seconds);
};

} // namespace clara

#endif // CLARA_WIFI_AUDITOR_H
