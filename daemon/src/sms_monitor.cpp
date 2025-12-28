/**
 * CLARA Security - SMS Monitor Implementation
 *
 * Root yetkisiyle SMS veritabanını izler ve phishing tespiti yapar.
 */

#include "../include/sms_monitor.h"
#include <algorithm>
#include <chrono>
#include <regex>
#include <syslog.h>
#include <unistd.h>

// Koşullu SQLite include
#ifndef ANDROID_NO_EXTERNAL_LIBS
#include <sqlite3.h>
#define HAS_SQLITE3 1
#else
#define HAS_SQLITE3 0
#endif

namespace clara {

// SMS veritabanı yolu
[[maybe_unused]] constexpr const char *SMS_DB_PATH =
    "/data/data/com.android.providers.telephony/databases/mmssms.db";

// Alternatif yollar (Android versiyonuna göre değişebilir)
constexpr const char *SMS_DB_PATHS[] = {
    "/data/data/com.android.providers.telephony/databases/mmssms.db",
    "/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
    "/data/data/com.google.android.gms/databases/icing_mmssms.db"};

SmsMonitor::SmsMonitor() {
  // Phishing pattern'lerini yükle
  phishing_patterns_ = {
      std::regex(R"(https?://[^\s]+\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|pw|cc|ws)/)",
                 std::regex::icase),
      std::regex(R"(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd)", std::regex::icase),
      std::regex(R"((hesab|account|şifre|password|doğrula|verify).*https?://)",
                 std::regex::icase),
      std::regex(R"((banka|bank|kredi|credit|kart|card).*https?://)",
                 std::regex::icase),
      std::regex(R"((acil|urgent|hemen|immediately).*https?://)",
                 std::regex::icase)};

  suspicious_keywords_ = {
      // Türkçe
      "hesabınız askıya alındı", "hesabınız bloke", "şifrenizi güncelleyin",
      "ödeme bekliyor", "kart bilgilerinizi", "doğrulama gerekli", "son şans",
      "acil işlem", "hediye kazandınız", "milyoner oldunuz", "tıklayın kazanın",
      "ücretsiz iphone", "banka hesabınız",

      // İngilizce
      "account suspended", "verify your account", "click here to claim",
      "you've won", "urgent action required", "confirm your identity",
      "unusual activity", "unauthorized access", "reset your password"};
}

SmsMonitor::~SmsMonitor() { stop(); }

bool SmsMonitor::initialize() {
  syslog(LOG_INFO, "SMS Monitor başlatılıyor...");

  // SMS DB erişim kontrolü
  for (const char *db_path : SMS_DB_PATHS) {
    if (access(db_path, R_OK) == 0) {
      syslog(LOG_INFO, "SMS DB bulundu: %s", db_path);
      return true;
    }
  }

  syslog(LOG_WARNING, "SMS DB bulunamadı - SMS izleme devre dışı");
  return false;
}

void SmsMonitor::start() {
  if (running_.load())
    return;

  running_ = true;
  monitor_thread_ = std::thread(&SmsMonitor::monitorLoop, this);
  syslog(LOG_INFO, "SMS Monitor başlatıldı");
}

void SmsMonitor::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  syslog(LOG_INFO, "SMS Monitor durduruldu");
}

void SmsMonitor::monitorLoop() {
  while (running_.load()) {
    try {
      // Yeni SMS'leri oku
      auto new_sms = readNewSms();

      for (const auto &sms : new_sms) {
        scanned_count_++;

        // AI analizi
        ThreatInfo threat = analyzeSms(sms);

        if (threat.level >= ThreatLevel::MEDIUM) {
          // Güvenlik olayı oluştur
          SecurityEvent event;
          event.id =
              std::chrono::system_clock::now().time_since_epoch().count();
          event.timestamp = sms.timestamp;
          event.type = EventType::SMS_RECEIVED;
          event.level = threat.level;
          event.source = sms.sender;
          event.description = threat.description;
          event.handled = false;

          if (callback_) {
            callback_(event);
          }

          if (threat.level >= ThreatLevel::HIGH) {
            blocked_count_++;
            // Otomatik engelleme aktifse
            if (auto_block_) {
              // TODO: SMS'i spam olarak işaretle
            }
          }
        }
      }

    } catch (const std::exception &e) {
      syslog(LOG_ERR, "SMS Monitor hata: %s", e.what());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(check_interval_ms_));
  }
}

std::vector<SmsInfo> SmsMonitor::readNewSms() {
  std::vector<SmsInfo> result;

#if HAS_SQLITE3
  sqlite3 *db = nullptr;

  // SMS DB'yi aç
  const char *db_path = nullptr;
  for (const char *path : SMS_DB_PATHS) {
    if (access(path, R_OK) == 0) {
      db_path = path;
      break;
    }
  }

  if (!db_path)
    return result;

  int rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, nullptr);
  if (rc != SQLITE_OK) {
    syslog(LOG_ERR, "SMS DB açılamadı: %s", sqlite3_errmsg(db));
    return result;
  }

  // Son SMS ID'den sonraki mesajları sorgula
  std::string query = "SELECT _id, address, body, date, read, thread_id "
                      "FROM sms WHERE _id > ? AND type = 1 " // type=1: inbox
                      "ORDER BY date DESC LIMIT 50";

  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

  if (rc == SQLITE_OK) {
    sqlite3_bind_int64(stmt, 1, last_sms_id_);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      SmsInfo sms;

      int64_t id = sqlite3_column_int64(stmt, 0);

      const char *address = (const char *)sqlite3_column_text(stmt, 1);
      const char *body = (const char *)sqlite3_column_text(stmt, 2);

      sms.sender = address ? address : "";
      sms.body = body ? body : "";
      sms.timestamp = sqlite3_column_int64(stmt, 3);
      sms.is_read = sqlite3_column_int(stmt, 4) != 0;
      sms.thread_id = sqlite3_column_int(stmt, 5);

      result.push_back(sms);

      // En son ID'yi güncelle
      if (id > last_sms_id_) {
        last_sms_id_ = id;
      }
    }

    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
#else
  // Android fallback: content provider kullan
  std::string cmd = "content query --uri content://sms/inbox --projection "
                    "_id:address:body:date "
                    "--where \"_id>" +
                    std::to_string(last_sms_id_) +
                    "\" --sort \"date DESC\" 2>/dev/null | head -50";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (pipe) {
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
      // Parse: Row: 0 _id=123, address=+905XX, body=Hello, date=1234567890
      std::string line(buffer);
      SmsInfo sms;

      // Basit parsing
      size_t id_pos = line.find("_id=");
      size_t addr_pos = line.find("address=");
      size_t body_pos = line.find("body=");
      size_t date_pos = line.find("date=");

      if (id_pos != std::string::npos && addr_pos != std::string::npos) {
        // ID
        size_t id_end = line.find(",", id_pos);
        int64_t id = std::stoll(line.substr(id_pos + 4, id_end - id_pos - 4));

        // Address
        size_t addr_end = line.find(",", addr_pos);
        sms.sender = line.substr(addr_pos + 8, addr_end - addr_pos - 8);

        // Body
        if (body_pos != std::string::npos) {
          size_t body_end = line.find(", date=", body_pos);
          if (body_end != std::string::npos) {
            sms.body = line.substr(body_pos + 5, body_end - body_pos - 5);
          }
        }

        // Date
        if (date_pos != std::string::npos) {
          size_t date_end = line.find(",", date_pos);
          if (date_end == std::string::npos)
            date_end = line.length();
          sms.timestamp =
              std::stoull(line.substr(date_pos + 5, date_end - date_pos - 5));
        }

        sms.is_read = false;
        sms.thread_id = 0;

        result.push_back(sms);

        if (id > last_sms_id_) {
          last_sms_id_ = id;
        }
      }
    }
    pclose(pipe);
  }
#endif
  return result;
}

ThreatInfo SmsMonitor::analyzeSms(const SmsInfo &sms) {
  ThreatInfo threat;
  threat.source = sms.sender;
  threat.raw_data = sms.body;

  float risk_score = calculateRiskScore(sms);

  // Tehdit seviyesini belirle
  if (risk_score >= 0.9) {
    threat.level = ThreatLevel::CRITICAL;
    threat.type = "phishing_critical";
    threat.description = "Kritik phishing SMS tespit edildi: " + sms.sender;
  } else if (risk_score >= 0.7) {
    threat.level = ThreatLevel::HIGH;
    threat.type = "phishing_high";
    threat.description = "Yüksek olasılıklı phishing SMS: " + sms.sender;
  } else if (risk_score >= 0.5) {
    threat.level = ThreatLevel::MEDIUM;
    threat.type = "spam_suspicious";
    threat.description = "Şüpheli SMS: " + sms.sender;
  } else if (risk_score >= 0.3) {
    threat.level = ThreatLevel::LOW;
    threat.type = "spam_possible";
    threat.description = "Olası spam SMS: " + sms.sender;
  } else {
    threat.level = ThreatLevel::NONE;
    threat.type = "safe";
    threat.description = "Güvenli SMS";
  }

  threat.confidence = risk_score;

  // Önerilen aksiyonlar
  if (threat.level >= ThreatLevel::HIGH) {
    threat.recommended_actions = {ActionType::NOTIFY, ActionType::BLOCK};
  } else if (threat.level >= ThreatLevel::MEDIUM) {
    threat.recommended_actions = {ActionType::NOTIFY};
  } else if (threat.level >= ThreatLevel::LOW) {
    threat.recommended_actions = {ActionType::LOG};
  }

  return threat;
}

float SmsMonitor::calculateRiskScore(const SmsInfo &sms) {
  float score = 0.0f;
  std::string body_lower = sms.body;
  std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(),
                 ::tolower);

  // 1. URL analizi (0-0.3 puan)
  std::regex url_regex(R"(https?://[^\s]+)", std::regex::icase);
  std::smatch url_match;
  std::string::const_iterator search_start = sms.body.cbegin();

  [[maybe_unused]] int url_count = 0;
  while (
      std::regex_search(search_start, sms.body.cend(), url_match, url_regex)) {
    url_count++;
    std::string url = url_match[0];

    // Kısa URL servisleri
    if (isPhishingUrl(url)) {
      score += 0.2f;
    }

    // Şüpheli TLD'ler
    if (url.find(".ru") != std::string::npos ||
        url.find(".cn") != std::string::npos ||
        url.find(".tk") != std::string::npos ||
        url.find(".ml") != std::string::npos ||
        url.find(".xyz") != std::string::npos) {
      score += 0.15f;
    }

    search_start = url_match.suffix().first;
  }

  // 2. Phishing keyword analizi (0-0.4 puan)
  int keyword_matches = 0;
  for (const auto &keyword : suspicious_keywords_) {
    if (body_lower.find(keyword) != std::string::npos) {
      keyword_matches++;
    }
  }
  score += std::min(0.4f, keyword_matches * 0.1f);

  // 3. Regex pattern analizi (0-0.3 puan)
  for (const auto &pattern : phishing_patterns_) {
    if (std::regex_search(sms.body, pattern)) {
      score += 0.15f;
    }
  }

  // 4. Sender analizi (0-0.2 puan)
  // Alfanumerik sender'lar daha güvenilir
  bool all_numeric = std::all_of(sms.sender.begin(), sms.sender.end(),
                                 [](char c) { return isdigit(c) || c == '+'; });

  // Çok kısa veya tuhaf sender
  if (sms.sender.length() < 5 && !all_numeric) {
    score += 0.1f;
  }

  // 5. Urgency indicators (0-0.2 puan)
  std::vector<std::string> urgency = {"acil",        "urgent",   "hemen",
                                      "immediately", "son şans", "last chance",
                                      "bugün",       "today"};
  for (const auto &word : urgency) {
    if (body_lower.find(word) != std::string::npos) {
      score += 0.1f;
      break;
    }
  }

  return std::min(1.0f, score);
}

bool SmsMonitor::isPhishingUrl(const std::string &url) {
  // Kısa URL servisleri
  std::vector<std::string> short_url_services = {
      "bit.ly",  "tinyurl.com", "t.co",    "goo.gl",
      "is.gd",   "buff.ly",     "ow.ly",   "tiny.cc",
      "lnkd.in", "rebrand.ly",  "cutt.ly", "shorturl.at"};

  for (const auto &service : short_url_services) {
    if (url.find(service) != std::string::npos) {
      return true;
    }
  }

  // IP adresi içeren URL'ler
  std::regex ip_regex(R"(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
  if (std::regex_search(url, ip_regex)) {
    return true;
  }

  return false;
}

bool SmsMonitor::containsSuspiciousKeywords(const std::string &text) {
  std::string lower = text;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

  for (const auto &keyword : suspicious_keywords_) {
    if (lower.find(keyword) != std::string::npos) {
      return true;
    }
  }
  return false;
}

} // namespace clara
