/**
 * CLARA Security - File Monitor Implementation
 *
 * Inotify ile dosya sistemi izleme ve malware tarama.
 */

#include "../include/file_monitor.h"
#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

// Koşullu include'lar
#ifndef ANDROID_NO_EXTERNAL_LIBS
#include <openssl/sha.h>
#include <zip.h>
#define HAS_OPENSSL 1
#define HAS_LIBZIP 1
#else
#define HAS_OPENSSL 0
#define HAS_LIBZIP 0
#endif

namespace clara {

// Inotify buffer boyutu
constexpr size_t INOTIFY_BUFFER_SIZE = 4096;

FileMonitor::FileMonitor() {
  // Varsayılan izleme dizinleri
  // Performans optimizasyonu: WhatsApp ve Telegram gibi çok dosyalı klasörleri
  // varsayılan taramadan çıkardık. Sadece Download ve DCIM (Kamera) ana
  // hedefler.
  watch_paths_ = {"/sdcard/Download", "/sdcard/DCIM", "/data/local/tmp"};

  // Taranacak uzantılar
  scan_extensions_ = {".apk", ".dex", ".so",  ".jar", ".zip",
                      ".sh",  ".py",  ".exe", ".bat", ".cmd"};
}

FileMonitor::~FileMonitor() {
  stop();

  if (inotify_fd_ >= 0) {
    close(inotify_fd_);
  }
}

bool FileMonitor::initialize() {
  syslog(LOG_INFO, "File Monitor başlatılıyor...");

  // Inotify başlat
  inotify_fd_ = inotify_init1(IN_NONBLOCK);
  if (inotify_fd_ < 0) {
    syslog(LOG_ERR, "Inotify başlatılamadı: %s", strerror(errno));
    return false;
  }

  // Malware hash veritabanını yükle
  loadMalwareHashes();

  // Karantina klasörünü oluştur
  mkdir(quarantine_path_.c_str(), 0700);

  return true;
}

void FileMonitor::loadMalwareHashes() {
  // Önceden bilinen malware hash'lerini yükle
  // Bu dosya güncellenebilir bir database'den gelecek
  std::ifstream hash_file("/data/clara/cache/malware_hashes.txt");

  if (hash_file.is_open()) {
    std::string line;
    while (std::getline(hash_file, line)) {
      if (!line.empty() && line[0] != '#') {
        malware_hashes_.insert(line);
      }
    }
    hash_file.close();
    syslog(LOG_INFO, "Malware hash DB yüklendi: %zu hash",
           malware_hashes_.size());
  }

  // Bazı örnek hash'ler (bilinen malware)
  // Bu liste güncellenmeli
  malware_hashes_.insert("e99a18c428cb38d5f260853678922e03");
  malware_hashes_.insert("d41d8cd98f00b204e9800998ecf8427e");
}

void FileMonitor::start() {
  if (running_.load())
    return;

  // Watch'ları ekle
  for (const auto &path : watch_paths_) {
    addWatchPath(path);
  }

  running_ = true;

  // Watch ekleme işlemini arka plana at (Asenkron)
  // Bu işlem uzun sürdüğü için ana thread'i (veya başlatıcıyı) bloklamamalı
  std::thread([this]() {
    syslog(LOG_INFO, "Watch listesi oluşturuluyor (Asenkron)...");
    for (const auto &path : watch_paths_) {
      // Her ana klasör arasında da bekle
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      addWatchPath(path);
    }
    syslog(LOG_INFO, "Watch listesi tamamlandı. File Monitor aktif.");
  }).detach();

  monitor_thread_ = std::thread(&FileMonitor::monitorLoop, this);
  syslog(LOG_INFO, "File Monitor başlatıldı");
}

void FileMonitor::stop() {
  running_ = false;

  // Watch'ları kaldır
  for (const auto &[wd, path] : watch_descriptors_) {
    inotify_rm_watch(inotify_fd_, wd);
  }
  watch_descriptors_.clear();

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  syslog(LOG_INFO, "File Monitor durduruldu");
}

void FileMonitor::addWatchPath(const std::string &path) {
  if (inotify_fd_ < 0)
    return;

  // Ana dizini izle
  int wd =
      inotify_add_watch(inotify_fd_, path.c_str(),
                        IN_CREATE | IN_MODIFY | IN_MOVED_TO | IN_CLOSE_WRITE);

  if (wd >= 0) {
    watch_descriptors_[wd] = path;
    syslog(LOG_INFO, "Watch eklendi: %s (wd=%d)", path.c_str(), wd);
  } else {
    syslog(LOG_WARNING, "Watch eklenemedi: %s (%s)", path.c_str(),
           strerror(errno));
  }

  // Alt dizinleri de ekle (recursive)
  DIR *dir = opendir(path.c_str());
  if (dir) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
      if (entry->d_type == DT_DIR) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
          std::string subpath = path + "/" + entry->d_name;
          // Recursive olarak alt dizinleri de ekle (max 3 seviye)
          int depth = std::count(subpath.begin(), subpath.end(), '/');
          if (depth < 6) { // ~3 level depth limit
            addWatchPath(subpath);
          }
        }
      }
    }
    closedir(dir);
  }
}

void FileMonitor::removeWatchPath(const std::string &path) {
  for (auto it = watch_descriptors_.begin(); it != watch_descriptors_.end();) {
    if (it->second == path) {
      inotify_rm_watch(inotify_fd_, it->first);
      it = watch_descriptors_.erase(it);
    } else {
      ++it;
    }
  }
}

void FileMonitor::monitorLoop() {
  char buffer[INOTIFY_BUFFER_SIZE];

  while (running_.load()) {
    ssize_t length = read(inotify_fd_, buffer, INOTIFY_BUFFER_SIZE);

    if (length > 0) {
      size_t i = 0;
      while (i < static_cast<size_t>(length)) {
        auto *event = reinterpret_cast<inotify_event *>(&buffer[i]);

        if (event->len > 0) {
          auto it = watch_descriptors_.find(event->wd);
          if (it != watch_descriptors_.end()) {
            handleInotifyEvent(event, it->second);
          }
        }

        i += sizeof(inotify_event) + event->len;
      }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void FileMonitor::handleInotifyEvent(const inotify_event *event,
                                     const std::string &base_path) {
  std::string filename(event->name);
  std::string full_path = base_path + "/" + filename;

  // Dizin oluşturulduysa watch ekle
  if (event->mask & IN_ISDIR) {
    if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
      addWatchPath(full_path);
    }
    return;
  }

  // Dosya olaylarını işle
  if (event->mask & (IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO)) {
    // Taranması gereken dosya mı?
    if (!shouldScan(full_path)) {
      return;
    }

    syslog(LOG_INFO, "Yeni dosya tespit edildi: %s", full_path.c_str());

    // Dosyayı tara
    ThreatInfo threat = scanFile(full_path);
    scanned_count_++;

    if (threat.level >= ThreatLevel::MEDIUM) {
      // Güvenlik olayı oluştur
      SecurityEvent sec_event;
      sec_event.id =
          std::chrono::system_clock::now().time_since_epoch().count();
      sec_event.timestamp =
          std::chrono::system_clock::now().time_since_epoch().count();
      sec_event.type = EventType::FILE_SCANNED;
      sec_event.level = threat.level;
      sec_event.source = full_path;
      sec_event.description = threat.description;
      sec_event.handled = false;

      if (callback_) {
        callback_(sec_event);
      }

      // Yüksek tehdit - karantinaya al
      if (threat.level >= ThreatLevel::HIGH && auto_quarantine_) {
        quarantineFile(full_path);
      }
    }
  }
}

bool FileMonitor::shouldScan(const std::string &path) {
  // Uzantı kontrolü
  for (const auto &ext : scan_extensions_) {
    if (path.length() >= ext.length()) {
      std::string file_ext = path.substr(path.length() - ext.length());
      std::transform(file_ext.begin(), file_ext.end(), file_ext.begin(),
                     ::tolower);
      if (file_ext == ext) {
        return true;
      }
    }
  }
  return false;
}

ThreatInfo FileMonitor::scanFile(const std::string &path) {
  ThreatInfo threat;
  threat.source = path;

  FileInfo info = getFileInfo(path);
  if (info.path.empty()) {
    threat.level = ThreatLevel::NONE;
    threat.description = "Dosya okunamadı";
    return threat;
  }

  float risk_score = 0.0f;

  // 1. Hash kontrolü - bilinen malware
  if (!info.sha256_hash.empty() && isKnownMalware(info.sha256_hash)) {
    threat.level = ThreatLevel::CRITICAL;
    threat.type = "known_malware";
    threat.description = "Bilinen malware tespit edildi: " + info.name;
    threat.confidence = 1.0f;
    threat.recommended_actions = {ActionType::QUARANTINE, ActionType::NOTIFY};
    return threat;
  }

  // 2. APK özel analizi
  if (info.is_apk) {
    threat = analyzeApk(path);
    if (threat.level >= ThreatLevel::HIGH) {
      return threat;
    }
    risk_score += threat.confidence * 0.5f;
  }

  // 3. Dosya adı analizi
  std::string name_lower = info.name;
  std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                 ::tolower);

  // Şüpheli dosya adı pattern'leri
  std::vector<std::string> suspicious_names = {
      "hack", "crack",  "keygen",  "patch",   "loader", "injector", "bot",
      "rat",  "trojan", "exploit", "payload", "shell",  "backdoor", "rootkit"};

  for (const auto &pattern : suspicious_names) {
    if (name_lower.find(pattern) != std::string::npos) {
      risk_score += 0.3f;
      break;
    }
  }

  // 4. Boyut analizi (çok küçük veya çok büyük APK'lar şüpheli)
  if (info.is_apk) {
    if (info.size < 50 * 1024) { // 50KB altı
      risk_score += 0.2f;
    } else if (info.size > 200 * 1024 * 1024) { // 200MB üstü
      risk_score += 0.1f;
    }
  }

  // AI analizi (aktifse)
  if (ai_enabled_) {
    auto &daemon = ClaraDaemon::getInstance();
    auto ai = daemon.getAiEngine();
    if (ai) {
      ThreatInfo ai_threat = ai->analyzeFile(info);
      risk_score += ai_threat.confidence * 0.4f;
    }
  }

  // Sonuç
  risk_score = std::min(1.0f, risk_score);
  threat.confidence = risk_score;

  if (risk_score >= 0.8f) {
    threat.level = ThreatLevel::HIGH;
    threat.type = "suspicious_file";
    threat.description = "Yüksek riskli dosya: " + info.name;
  } else if (risk_score >= 0.5f) {
    threat.level = ThreatLevel::MEDIUM;
    threat.type = "possibly_unsafe";
    threat.description = "Şüpheli dosya: " + info.name;
  } else if (risk_score >= 0.3f) {
    threat.level = ThreatLevel::LOW;
    threat.type = "low_risk";
    threat.description = "Düşük risk: " + info.name;
  } else {
    threat.level = ThreatLevel::NONE;
    threat.type = "safe";
    threat.description = "Güvenli dosya: " + info.name;
  }

  return threat;
}

ThreatInfo FileMonitor::analyzeApk(const std::string &apk_path) {
  ThreatInfo threat;
  threat.source = apk_path;

  float risk_score = 0.0f;

  // İzinleri çıkar
  auto permissions = extractApkPermissions(apk_path);

  // Tehlikeli izin sayısı
  std::vector<std::string> dangerous = {"SEND_SMS",
                                        "READ_SMS",
                                        "RECEIVE_SMS",
                                        "READ_CONTACTS",
                                        "WRITE_CONTACTS",
                                        "RECORD_AUDIO",
                                        "CAMERA",
                                        "ACCESS_FINE_LOCATION",
                                        "READ_CALL_LOG",
                                        "WRITE_CALL_LOG",
                                        "SYSTEM_ALERT_WINDOW",
                                        "REQUEST_INSTALL_PACKAGES",
                                        "BIND_ACCESSIBILITY_SERVICE",
                                        "BIND_DEVICE_ADMIN"};

  int dangerous_count = 0;
  for (const auto &perm : permissions) {
    for (const auto &d : dangerous) {
      if (perm.find(d) != std::string::npos) {
        dangerous_count++;
      }
    }
  }

  // 5+ tehlikeli izin çok şüpheli
  if (dangerous_count >= 5) {
    risk_score += 0.5f;
  } else if (dangerous_count >= 3) {
    risk_score += 0.3f;
  } else if (dangerous_count >= 1) {
    risk_score += 0.15f;
  }

  // Accessibility + Device Admin kombinasyonu çok tehlikeli
  bool has_accessibility = false;
  bool has_device_admin = false;
  for (const auto &perm : permissions) {
    if (perm.find("ACCESSIBILITY") != std::string::npos)
      has_accessibility = true;
    if (perm.find("DEVICE_ADMIN") != std::string::npos)
      has_device_admin = true;
  }

  if (has_accessibility && has_device_admin) {
    risk_score += 0.4f;
    threat.type = "banking_trojan_suspect";
  }

  threat.confidence = std::min(1.0f, risk_score);

  if (risk_score >= 0.7f) {
    threat.level = ThreatLevel::HIGH;
    threat.description = "Yüksek riskli APK - " +
                         std::to_string(dangerous_count) + " tehlikeli izin";
  } else if (risk_score >= 0.4f) {
    threat.level = ThreatLevel::MEDIUM;
    threat.description =
        "Şüpheli APK - " + std::to_string(dangerous_count) + " tehlikeli izin";
  } else {
    threat.level = ThreatLevel::LOW;
    threat.description = "Normal APK";
  }

  return threat;
}

std::vector<std::string>
FileMonitor::extractApkPermissions(const std::string &apk_path) {
  std::vector<std::string> permissions;

#if HAS_LIBZIP
  // libzip ile APK aç
  int err;
  zip_t *archive = zip_open(apk_path.c_str(), ZIP_RDONLY, &err);
  if (!archive) {
    return permissions;
  }

  // AndroidManifest.xml bul
  zip_stat_t stat;
  if (zip_stat(archive, "AndroidManifest.xml", 0, &stat) == 0) {
    // Binary XML - basit string arama
    zip_file_t *file = zip_fopen(archive, "AndroidManifest.xml", 0);
    if (file) {
      std::vector<char> buffer(stat.size);
      zip_fread(file, buffer.data(), stat.size);
      zip_fclose(file);

      // Binary XML'den permission string'lerini çıkar
      std::string content(buffer.begin(), buffer.end());

      // "permission" kelimesini ara
      std::vector<std::string> common_perms = {"SEND_SMS",
                                               "READ_SMS",
                                               "RECEIVE_SMS",
                                               "INTERNET",
                                               "READ_CONTACTS",
                                               "WRITE_CONTACTS",
                                               "CAMERA",
                                               "RECORD_AUDIO",
                                               "ACCESS_FINE_LOCATION",
                                               "ACCESS_COARSE_LOCATION",
                                               "READ_EXTERNAL_STORAGE",
                                               "WRITE_EXTERNAL_STORAGE",
                                               "READ_PHONE_STATE",
                                               "CALL_PHONE",
                                               "READ_CALL_LOG",
                                               "SYSTEM_ALERT_WINDOW",
                                               "REQUEST_INSTALL_PACKAGES",
                                               "BIND_ACCESSIBILITY_SERVICE",
                                               "BIND_DEVICE_ADMIN"};

      for (const auto &perm : common_perms) {
        if (content.find(perm) != std::string::npos) {
          permissions.push_back("android.permission." + perm);
        }
      }
    }
  }

  zip_close(archive);
#else
  // Android fallback: aapt veya pm komutu kullan
  std::string cmd =
      "aapt dump permissions '" + apk_path +
      "' 2>/dev/null | grep 'uses-permission' | sed \"s/.*'\\(.*\\)'.*/\\1/\"";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (pipe) {
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) {
      std::string perm(buffer);
      if (!perm.empty() && perm.back() == '\n') {
        perm.pop_back();
      }
      if (!perm.empty()) {
        permissions.push_back(perm);
      }
    }
    pclose(pipe);
  }
#endif
  return permissions;
}

FileInfo FileMonitor::getFileInfo(const std::string &path) {
  FileInfo info;

  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    return info;
  }

  info.path = path;
  info.size = st.st_size;
  info.modified_time = st.st_mtime;

  // Dosya adı
  size_t last_slash = path.find_last_of('/');
  info.name =
      (last_slash != std::string::npos) ? path.substr(last_slash + 1) : path;

  // Uzantı
  size_t last_dot = info.name.find_last_of('.');
  info.extension =
      (last_dot != std::string::npos) ? info.name.substr(last_dot) : "";

  // APK kontrolü
  std::string ext_lower = info.extension;
  std::transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(),
                 ::tolower);
  info.is_apk = (ext_lower == ".apk");

  // SHA256 hash
  info.sha256_hash = calculateSha256(path);

  return info;
}

std::string FileMonitor::calculateSha256(const std::string &path) {
#if HAS_OPENSSL
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return "";
  }

  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  char buffer[8192];
  while (file.read(buffer, sizeof(buffer))) {
    SHA256_Update(&sha256, buffer, file.gcount());
  }
  SHA256_Update(&sha256, buffer, file.gcount());

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &sha256);

  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }

  return ss.str();
#else
  // Android fallback: shell kullan
  std::string cmd = "sha256sum '" + path + "' 2>/dev/null | cut -d' ' -f1";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    return "";

  char buffer[128];
  std::string result;
  if (fgets(buffer, sizeof(buffer), pipe)) {
    result = buffer;
    // Satır sonu karakterini kaldır
    if (!result.empty() && result.back() == '\n') {
      result.pop_back();
    }
  }
  pclose(pipe);
  return result;
#endif
}

bool FileMonitor::isKnownMalware(const std::string &hash) {
  return malware_hashes_.find(hash) != malware_hashes_.end();
}

void FileMonitor::quarantineFile(const std::string &path) {
  // Dosya adını al
  size_t last_slash = path.find_last_of('/');
  std::string filename =
      (last_slash != std::string::npos) ? path.substr(last_slash + 1) : path;

  // Zaman damgası ekle
  auto now = std::chrono::system_clock::now();
  auto timestamp =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count();

  std::string quarantine_filename = quarantine_path_ + "/" +
                                    std::to_string(timestamp) + "_" + filename +
                                    ".quarantine";

  // Dosyayı taşı
  if (rename(path.c_str(), quarantine_filename.c_str()) == 0) {
    syslog(LOG_INFO, "Dosya karantinaya alındı: %s", path.c_str());
    quarantined_count_++;

    // Olay oluştur
    SecurityEvent event;
    event.id = timestamp;
    event.timestamp = timestamp;
    event.type = EventType::FILE_QUARANTINED;
    event.level = ThreatLevel::HIGH;
    event.source = path;
    event.description = "Dosya karantinaya alındı: " + filename;
    event.handled = true;

    if (callback_) {
      callback_(event);
    }
  } else {
    syslog(LOG_ERR, "Karantina başarısız: %s (%s)", path.c_str(),
           strerror(errno));
  }
}

} // namespace clara
