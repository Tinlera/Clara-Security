/**
 * CLARA Security - Messenger Monitor Implementation
 * WhatsApp ve Telegram mesajlarını izler
 */

#include "../include/messenger_monitor.h"
#include <algorithm>
#include <chrono>
#include <fstream>
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

// WhatsApp veritabanı yolları
const std::vector<std::string> WHATSAPP_DB_PATHS = {
    "/data/data/com.whatsapp/databases/msgstore.db",
    "/data/data/com.whatsapp/databases/wa.db",
    "/data/user/0/com.whatsapp/databases/msgstore.db"};

// Telegram veritabanı yolları
const std::vector<std::string> TELEGRAM_DB_PATHS = {
    "/data/data/org.telegram.messenger/files/cache4.db",
    "/data/user/0/org.telegram.messenger/files/cache4.db"};

MessengerMonitor::MessengerMonitor() {
  // Varsayılan olarak WhatsApp ve Telegram aktif
  enabled_apps_[MessengerApp::WHATSAPP] = true;
  enabled_apps_[MessengerApp::TELEGRAM] = true;
  enabled_apps_[MessengerApp::SIGNAL] = false;
  enabled_apps_[MessengerApp::INSTAGRAM] = false;
  enabled_apps_[MessengerApp::FACEBOOK_MESSENGER] = false;

  // Son mesaj ID'lerini sıfırla
  last_message_ids_[MessengerApp::WHATSAPP] = 0;
  last_message_ids_[MessengerApp::TELEGRAM] = 0;
}

MessengerMonitor::~MessengerMonitor() { stop(); }

bool MessengerMonitor::initialize() {
  syslog(LOG_INFO, "Messenger Monitor başlatılıyor...");

  bool found_any = false;

  // WhatsApp DB kontrolü
  for (const auto &path : WHATSAPP_DB_PATHS) {
    if (access(path.c_str(), R_OK) == 0) {
      syslog(LOG_INFO, "WhatsApp DB bulundu: %s", path.c_str());
      found_any = true;
      break;
    }
  }

  // Telegram DB kontrolü
  for (const auto &path : TELEGRAM_DB_PATHS) {
    if (access(path.c_str(), R_OK) == 0) {
      syslog(LOG_INFO, "Telegram DB bulundu: %s", path.c_str());
      found_any = true;
      break;
    }
  }

  if (!found_any) {
    syslog(LOG_WARNING,
           "Hiçbir messenger DB bulunamadı - notification modu kullanılacak");
    use_notification_method_ = true;
  }

  return true;
}

void MessengerMonitor::start() {
  if (running_.load())
    return;

  running_ = true;
  monitor_thread_ = std::thread(&MessengerMonitor::monitorLoop, this);
  syslog(LOG_INFO, "Messenger Monitor başlatıldı");
}

void MessengerMonitor::stop() {
  running_ = false;

  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }

  syslog(LOG_INFO, "Messenger Monitor durduruldu");
}

void MessengerMonitor::enableApp(MessengerApp app) {
  enabled_apps_[app] = true;
}

void MessengerMonitor::disableApp(MessengerApp app) {
  enabled_apps_[app] = false;
}

void MessengerMonitor::monitorLoop() {
  while (running_.load()) {
    try {
      // WhatsApp mesajlarını oku
      if (enabled_apps_[MessengerApp::WHATSAPP]) {
        auto messages = readWhatsAppMessages();
        for (const auto &msg : messages) {
          scanned_count_++;
          if (callback_) {
            callback_(msg);
          }
        }
      }

      // Telegram mesajlarını oku
      if (enabled_apps_[MessengerApp::TELEGRAM]) {
        auto messages = readTelegramMessages();
        for (const auto &msg : messages) {
          scanned_count_++;
          if (callback_) {
            callback_(msg);
          }
        }
      }

    } catch (const std::exception &e) {
      syslog(LOG_ERR, "Messenger Monitor hata: %s", e.what());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(check_interval_ms_));
  }
}

std::string MessengerMonitor::getWhatsAppDbPath() {
  for (const auto &path : WHATSAPP_DB_PATHS) {
    if (access(path.c_str(), R_OK) == 0) {
      return path;
    }
  }
  return "";
}

std::string MessengerMonitor::getTelegramDbPath() {
  for (const auto &path : TELEGRAM_DB_PATHS) {
    if (access(path.c_str(), R_OK) == 0) {
      return path;
    }
  }
  return "";
}

std::vector<MessengerMessage> MessengerMonitor::readWhatsAppMessages() {
  std::vector<MessengerMessage> messages;

#if HAS_SQLITE3
  std::string db_path = getWhatsAppDbPath();
  if (db_path.empty())
    return messages;

  sqlite3 *db = nullptr;
  int rc = sqlite3_open_v2(db_path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);

  if (rc != SQLITE_OK) {
    syslog(LOG_ERR, "WhatsApp DB açılamadı: %s", sqlite3_errmsg(db));
    return messages;
  }

  // Son ID'den sonraki mesajları sorgula
  // WhatsApp'ın message tablosu yapısı (versiyon bağımlı)
  std::string query = R"(
        SELECT _id, key_remote_jid, data, timestamp, key_from_me
        FROM messages
        WHERE _id > ? AND data IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 50
    )";

  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

  if (rc == SQLITE_OK) {
    sqlite3_bind_int64(stmt, 1, last_message_ids_[MessengerApp::WHATSAPP]);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      MessengerMessage msg;
      msg.app = "whatsapp";

      int64_t id = sqlite3_column_int64(stmt, 0);
      const char *sender = (const char *)sqlite3_column_text(stmt, 1);
      const char *content = (const char *)sqlite3_column_text(stmt, 2);

      msg.sender = sender ? sender : "";
      msg.content = content ? content : "";
      msg.timestamp = sqlite3_column_int64(stmt, 3);
      msg.chat_id = msg.sender;

      // URL'leri çıkar
      msg.urls = extractUrls(msg.content);

      // Sadece URL içeren mesajları işle
      if (!msg.urls.empty()) {
        messages.push_back(msg);
      }

      // Son ID'yi güncelle
      if (id > last_message_ids_[MessengerApp::WHATSAPP]) {
        last_message_ids_[MessengerApp::WHATSAPP] = id;
      }
    }

    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
#else
  // Android'de SQLite yoksa notification listener modunu kullan
  // Bu mod Android App tarafından yönetilir
  syslog(LOG_DEBUG, "WhatsApp mesajları notification modunda izleniyor");
#endif
  return messages;
}

std::vector<MessengerMessage> MessengerMonitor::readTelegramMessages() {
  std::vector<MessengerMessage> messages;

#if HAS_SQLITE3
  std::string db_path = getTelegramDbPath();
  if (db_path.empty())
    return messages;

  sqlite3 *db = nullptr;
  int rc = sqlite3_open_v2(db_path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);

  if (rc != SQLITE_OK) {
    syslog(LOG_ERR, "Telegram DB açılamadı: %s", sqlite3_errmsg(db));
    return messages;
  }

  // Telegram'ın mesaj yapısı
  std::string query = R"(
        SELECT mid, uid, data, date
        FROM messages
        WHERE mid > ?
        ORDER BY date DESC
        LIMIT 50
    )";

  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

  if (rc == SQLITE_OK) {
    sqlite3_bind_int64(stmt, 1, last_message_ids_[MessengerApp::TELEGRAM]);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      MessengerMessage msg;
      msg.app = "telegram";

      int64_t id = sqlite3_column_int64(stmt, 0);
      int64_t uid = sqlite3_column_int64(stmt, 1);

      // Telegram data blob'unu parse etmek karmaşık
      // Basit yaklaşım: blob içinde URL ara
      const void *blob = sqlite3_column_blob(stmt, 2);
      int blob_size = sqlite3_column_bytes(stmt, 2);

      if (blob && blob_size > 0) {
        std::string content((const char *)blob, blob_size);
        msg.content = content;
        msg.urls = extractUrls(content);
      }

      msg.sender = std::to_string(uid);
      msg.timestamp = sqlite3_column_int64(stmt, 3);
      msg.chat_id = msg.sender;

      if (!msg.urls.empty()) {
        messages.push_back(msg);
      }

      if (id > last_message_ids_[MessengerApp::TELEGRAM]) {
        last_message_ids_[MessengerApp::TELEGRAM] = id;
      }
    }

    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
#else
  // Android'de SQLite yoksa notification listener modunu kullan
  syslog(LOG_DEBUG, "Telegram mesajları notification modunda izleniyor");
#endif
  return messages;
}

std::vector<std::string>
MessengerMonitor::extractUrls(const std::string &text) {
  std::vector<std::string> urls;

  std::regex url_regex(R"(https?://[^\s<>"']+|www\.[^\s<>"']+)",
                       std::regex::icase);

  std::sregex_iterator it(text.begin(), text.end(), url_regex);
  std::sregex_iterator end;

  while (it != end) {
    urls.push_back(it->str());
    ++it;
  }

  return urls;
}

float MessengerMonitor::analyzeUrl(const std::string &url) {
  float risk = 0.0f;

  // Kısa URL servisleri
  std::vector<std::string> short_urls = {
      "bit.ly",  "tinyurl.com", "t.co",    "goo.gl",  "is.gd",
      "buff.ly", "ow.ly",       "tiny.cc", "cutt.ly", "rebrand.ly"};

  for (const auto &short_url : short_urls) {
    if (url.find(short_url) != std::string::npos) {
      risk += 0.4f;
      break;
    }
  }

  // IP adresi
  std::regex ip_regex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
  if (std::regex_search(url, ip_regex)) {
    risk += 0.3f;
  }

  // Şüpheli TLD'ler
  std::vector<std::string> bad_tlds = {".ru",  ".cn",  ".tk", ".ml",
                                       ".xyz", ".top", ".pw"};
  for (const auto &tld : bad_tlds) {
    if (url.find(tld) != std::string::npos) {
      risk += 0.2f;
      break;
    }
  }

  return std::min(1.0f, risk);
}

std::vector<MessengerMessage>
MessengerMonitor::scanRecentMessages(MessengerApp app, int count) {
  std::vector<MessengerMessage> messages;

  switch (app) {
  case MessengerApp::WHATSAPP:
    messages = readWhatsAppMessages();
    break;
  case MessengerApp::TELEGRAM:
    messages = readTelegramMessages();
    break;
  default:
    syslog(LOG_WARNING, "Desteklenmeyen messenger: %d", static_cast<int>(app));
    break;
  }

  if (messages.size() > static_cast<size_t>(count)) {
    messages.resize(count);
  }

  return messages;
}

} // namespace clara
