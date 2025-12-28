/**
 * CLARA Security - Tracker Blocker Implementation
 * Hosts dosyası tabanlı tracker/reklam engelleme
 */

#include "../include/tracker_blocker.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <syslog.h>

// Koşullu cURL include
#ifndef ANDROID_NO_EXTERNAL_LIBS
#include <curl/curl.h>
#define HAS_CURL 1
#else
#define HAS_CURL 0
#endif

namespace clara {

#if HAS_CURL
// CURL write callback
static size_t WriteCallback(void *contents, size_t size, size_t nmemb,
                            std::string *userp) {
  userp->append((char *)contents, size * nmemb);
  return size * nmemb;
}
#endif

TrackerBlocker::TrackerBlocker() {
  syslog(LOG_INFO, "Tracker Blocker oluşturuluyor...");

  // Varsayılan whitelist
  whitelist_ = {"localhost", "localhost.localdomain", "local"};
}

TrackerBlocker::~TrackerBlocker() {
  stop();
  restoreOriginalHosts();
}

bool TrackerBlocker::initialize() {
  syslog(LOG_INFO, "Tracker Blocker başlatılıyor...");

  // Cache klasörünü oluştur
  mkdir(cache_path_.c_str(), 0755);

  // Orijinal hosts dosyasını yedekle
  backupHostsFile();

#if HAS_CURL
  // CURL başlat
  curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

  return true;
}

void TrackerBlocker::start() {
  if (running_.load())
    return;

  running_ = true;

  // İlk güncelleme
  updateBlocklists();
  updateHostsFile();

  monitor_thread_ = std::thread(&TrackerBlocker::monitorLoop, this);

  syslog(LOG_INFO, "Tracker Blocker başlatıldı - %d domain engellendi",
         getBlockedDomainCount());
}

void TrackerBlocker::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  if (dns_thread_.joinable()) {
    dns_thread_.join();
  }

#if HAS_CURL
  curl_global_cleanup();
#endif

  syslog(LOG_INFO, "Tracker Blocker durduruldu");
}

void TrackerBlocker::monitorLoop() {
  auto last_update = std::chrono::steady_clock::now();

  while (running_.load()) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed =
        std::chrono::duration_cast<std::chrono::hours>(now - last_update);

    // Periyodik güncelleme
    if (elapsed.count() >= update_interval_hours_) {
      updateBlocklists();
      updateHostsFile();
      last_update = now;
    }

    std::this_thread::sleep_for(std::chrono::minutes(1));
  }
}

bool TrackerBlocker::backupHostsFile() {
  std::ifstream src(hosts_path_, std::ios::binary);
  std::ofstream dst(backup_path_, std::ios::binary);

  if (!src.is_open() || !dst.is_open()) {
    syslog(LOG_ERR, "Hosts dosyası yedeklenemedi");
    return false;
  }

  dst << src.rdbuf();

  syslog(LOG_INFO, "Hosts dosyası yedeklendi: %s", backup_path_.c_str());
  return true;
}

bool TrackerBlocker::restoreOriginalHosts() {
  std::ifstream src(backup_path_, std::ios::binary);

  if (!src.is_open()) {
    syslog(LOG_WARNING, "Yedek hosts dosyası bulunamadı");
    return false;
  }

  // /system'i yazılabilir yap
  system("mount -o remount,rw /system 2>/dev/null");

  std::ofstream dst(hosts_path_, std::ios::binary);
  if (!dst.is_open()) {
    syslog(LOG_ERR, "Hosts dosyası yazılamadı");
    return false;
  }

  dst << src.rdbuf();

  // /system'i tekrar salt okunur yap
  system("mount -o remount,ro /system 2>/dev/null");

  syslog(LOG_INFO, "Orijinal hosts dosyası geri yüklendi");
  return true;
}

std::unordered_set<std::string>
TrackerBlocker::downloadBlocklist(const std::string &url) {
  std::unordered_set<std::string> domains;

#if HAS_CURL
  CURL *curl = curl_easy_init();
  if (!curl) {
    return domains;
  }

  std::string response;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "CLARA-Security/1.0");

  CURLcode res = curl_easy_perform(curl);

  if (res == CURLE_OK) {
    domains = parseHostsFile(response);
    syslog(LOG_INFO, "Blocklist indirildi: %s (%zu domain)", url.c_str(),
           domains.size());
  } else {
    syslog(LOG_ERR, "Blocklist indirilemedi: %s - %s", url.c_str(),
           curl_easy_strerror(res));
  }

  curl_easy_cleanup(curl);
#else
  // Android fallback: wget/curl shell komutu kullan
  std::string cmd = "wget -q -O - '" + url + "' 2>/dev/null || curl -s '" +
                    url + "' 2>/dev/null";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (pipe) {
    std::string response;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
      response += buffer;
    }
    pclose(pipe);

    if (!response.empty()) {
      domains = parseHostsFile(response);
      syslog(LOG_INFO, "Blocklist indirildi: %s (%zu domain)", url.c_str(),
             domains.size());
    }
  }
#endif
  return domains;
}

std::unordered_set<std::string>
TrackerBlocker::parseHostsFile(const std::string &content) {
  std::unordered_set<std::string> domains;

  std::istringstream stream(content);
  std::string line;

  while (std::getline(stream, line)) {
    // Yorum satırlarını atla
    if (line.empty() || line[0] == '#') {
      continue;
    }

    // Baştaki boşlukları temizle
    size_t start = line.find_first_not_of(" \t");
    if (start == std::string::npos) {
      continue;
    }

    line = line.substr(start);

    // Format: "0.0.0.0 domain.com" veya "127.0.0.1 domain.com"
    std::istringstream line_stream(line);
    std::string ip, domain;

    line_stream >> ip >> domain;

    // IP kontrolü
    if ((ip == "0.0.0.0" || ip == "127.0.0.1") && !domain.empty()) {
      // Localhost ve benzeri girişleri atla
      if (domain != "localhost" && domain != "localhost.localdomain" &&
          domain.find("local") == std::string::npos) {
        domains.insert(domain);
      }
    }
  }

  return domains;
}

bool TrackerBlocker::updateBlocklists() {
  syslog(LOG_INFO, "Blocklist'ler güncelleniyor...");

  blocked_domains_.clear();
  domain_categories_.clear();

  for (const auto &source : blocklist_sources_) {
    if (!isCategoryEnabled(source.second)) {
      continue;
    }

    auto domains = downloadBlocklist(source.first);

    for (const auto &domain : domains) {
      blocked_domains_.insert(domain);
      domain_categories_[domain] = source.second;
    }
  }

  syslog(LOG_INFO, "Toplam %zu domain engellendi", blocked_domains_.size());
  return true;
}

std::string TrackerBlocker::generateHostsContent() {
  std::stringstream ss;

  // Header
  ss << "# CLARA Security - Tracker Blocker\n";
  ss << "# Generated at: "
     << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
  ss << "# Total domains: " << blocked_domains_.size() << "\n";
  ss << "#\n";

  // Localhost girişleri
  ss << "127.0.0.1 localhost\n";
  ss << "::1 localhost\n";
  ss << "\n";

  // Engellenen domainler
  for (const auto &domain : blocked_domains_) {
    // Whitelist kontrolü
    if (!isWhitelisted(domain)) {
      ss << "0.0.0.0 " << domain << "\n";
    }
  }

  return ss.str();
}

bool TrackerBlocker::updateHostsFile() {
  std::string content = generateHostsContent();

  return writeHostsFile(content);
}

std::string TrackerBlocker::readHostsFile() {
  std::ifstream file(hosts_path_);
  if (!file.is_open()) {
    return "";
  }

  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

bool TrackerBlocker::writeHostsFile(const std::string &content) {
  // /system'i yazılabilir yap
  system("mount -o remount,rw /system 2>/dev/null");

  std::ofstream file(hosts_path_);
  if (!file.is_open()) {
    syslog(LOG_ERR, "Hosts dosyası yazılamadı: %s", hosts_path_.c_str());
    return false;
  }

  file << content;
  file.close();

  // /system'i tekrar salt okunur yap
  system("mount -o remount,ro /system 2>/dev/null");

  syslog(LOG_INFO, "Hosts dosyası güncellendi");
  return true;
}

int TrackerBlocker::getBlockedDomainCount() { return blocked_domains_.size(); }

void TrackerBlocker::addBlocklist(const std::string &url,
                                  BlockCategory category) {
  blocklist_sources_.push_back({url, category});
  syslog(LOG_INFO, "Blocklist eklendi: %s", url.c_str());
}

void TrackerBlocker::removeBlocklist(const std::string &url) {
  blocklist_sources_.erase(
      std::remove_if(blocklist_sources_.begin(), blocklist_sources_.end(),
                     [&url](const auto &pair) { return pair.first == url; }),
      blocklist_sources_.end());

  syslog(LOG_INFO, "Blocklist kaldırıldı: %s", url.c_str());
}

void TrackerBlocker::blockDomain(const std::string &domain,
                                 BlockCategory category) {
  blocked_domains_.insert(domain);
  domain_categories_[domain] = category;

  updateHostsFile();

  syslog(LOG_INFO, "Domain engellendi: %s", domain.c_str());
}

void TrackerBlocker::unblockDomain(const std::string &domain) {
  blocked_domains_.erase(domain);
  domain_categories_.erase(domain);

  updateHostsFile();

  syslog(LOG_INFO, "Domain engeli kaldırıldı: %s", domain.c_str());
}

bool TrackerBlocker::isDomainBlocked(const std::string &domain) {
  return blocked_domains_.count(domain) > 0;
}

void TrackerBlocker::addToWhitelist(const std::string &domain) {
  whitelist_.insert(domain);
  syslog(LOG_INFO, "Whitelist'e eklendi: %s", domain.c_str());
}

void TrackerBlocker::removeFromWhitelist(const std::string &domain) {
  whitelist_.erase(domain);
  syslog(LOG_INFO, "Whitelist'ten çıkarıldı: %s", domain.c_str());
}

bool TrackerBlocker::isWhitelisted(const std::string &domain) {
  return whitelist_.count(domain) > 0;
}

void TrackerBlocker::enableCategory(BlockCategory category) {
  enabled_categories_.insert(category);
  syslog(LOG_INFO, "Kategori etkinleştirildi: %d", static_cast<int>(category));
}

void TrackerBlocker::disableCategory(BlockCategory category) {
  enabled_categories_.erase(category);
  syslog(LOG_INFO, "Kategori devre dışı: %d", static_cast<int>(category));
}

bool TrackerBlocker::isCategoryEnabled(BlockCategory category) {
  return enabled_categories_.count(category) > 0;
}

BlockerStats TrackerBlocker::getStats() { return stats_; }

std::vector<BlockedDomain> TrackerBlocker::getRecentlyBlocked(int count) {
  std::vector<BlockedDomain> result;

  int num = std::min(count, static_cast<int>(recent_blocks_.size()));
  for (int i = 0; i < num; i++) {
    result.push_back(recent_blocks_[recent_blocks_.size() - 1 - i]);
  }

  return result;
}

void TrackerBlocker::logBlock(const std::string &domain,
                              const std::string &app_package) {
  BlockedDomain block;
  block.domain = domain;
  block.last_blocked_time =
      std::chrono::system_clock::now().time_since_epoch().count();
  block.block_count = 1;

  if (domain_categories_.count(domain) > 0) {
    block.category = domain_categories_[domain];
  } else {
    block.category = BlockCategory::CUSTOM;
  }

  recent_blocks_.push_back(block);

  // Boyut kontrolü
  if (recent_blocks_.size() > 1000) {
    recent_blocks_.erase(recent_blocks_.begin());
  }

  // İstatistikleri güncelle
  stats_.total_blocked_today++;
  stats_.total_blocked_all_time++;
  stats_.blocks_by_category[block.category]++;
  stats_.top_blocked_domains[domain]++;
  stats_.top_blocking_apps[app_package]++;

  if (dns_callback_) {
    dns_callback_(domain, true);
  }
}

void TrackerBlocker::watchDnsQueries() {
  // DNS sorgularını logcat üzerinden izle
  // Bu VPN modunda daha etkili çalışır
  FILE *pipe = popen("logcat -s DNSResolver:* -v time", "r");

  if (!pipe) {
    syslog(LOG_ERR, "DNS logcat başlatılamadı");
    return;
  }

  std::array<char, 1024> buffer;

  while (running_.load() && fgets(buffer.data(), buffer.size(), pipe)) {
    std::string line(buffer.data());

    // DNS sorgusu içeren satırları parse et
    if (line.find("getaddrinfo") != std::string::npos ||
        line.find("resolv") != std::string::npos) {
      // Domain adını çıkar ve kontrol et
      // TODO: Daha detaylı parse
    }
  }

  pclose(pipe);
}

} // namespace clara
