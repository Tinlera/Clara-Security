/**
 * CLARA Security - Trust Engine Implementation
 */

#include "../include/trust_engine.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <regex>
#include <syslog.h>

// SQLite (opsiyonel)
#ifndef ANDROID_NO_EXTERNAL_LIBS
#include <sqlite3.h>
#define HAS_SQLITE3 1
#else
#define HAS_SQLITE3 0
#endif

namespace clara {

// Güvenilir mağazalar
static const std::unordered_map<std::string, InstallSource> STORE_PACKAGES = {
    {"com.android.vending", InstallSource::PLAY_STORE},
    {"com.google.android.packageinstaller", InstallSource::SIDELOAD},
    {"com.sec.android.app.samsungapps", InstallSource::GALAXY_STORE},
    {"com.xiaomi.mipicks", InstallSource::XIAOMI_STORE},
    {"com.xiaomi.market", InstallSource::XIAOMI_STORE},
    {"com.huawei.appmarket", InstallSource::HUAWEI_STORE},
    {"com.amazon.venezia", InstallSource::AMAZON_STORE},
    {"org.fdroid.fdroid", InstallSource::FDROID},
};

// Başlangıç puanları
static const std::unordered_map<InstallSource, int> INITIAL_SCORES = {
    {InstallSource::PLAY_STORE, 80},
    {InstallSource::GALAXY_STORE, 75},
    {InstallSource::XIAOMI_STORE, 75},
    {InstallSource::HUAWEI_STORE, 75},
    {InstallSource::AMAZON_STORE, 70},
    {InstallSource::FDROID, 85},   // F-Droid = açık kaynak, güvenilir
    {InstallSource::SIDELOAD, 20}, // Bilinmeyen kaynak = düşük
    {InstallSource::ADB, 30},
    {InstallSource::SYSTEM, 100},
    {InstallSource::UNKNOWN, 20},
};

// Maksimum erişilebilir puanlar
static const std::unordered_map<InstallSource, int> MAX_SCORES = {
    {InstallSource::PLAY_STORE, 95},   {InstallSource::GALAXY_STORE, 90},
    {InstallSource::XIAOMI_STORE, 90}, {InstallSource::HUAWEI_STORE, 90},
    {InstallSource::AMAZON_STORE, 85}, {InstallSource::FDROID, 95},
    {InstallSource::SIDELOAD, 70}, // Sideload asla 70'i geçemez
    {InstallSource::ADB, 75},          {InstallSource::SYSTEM, 100},
    {InstallSource::UNKNOWN, 60},
};

TrustEngine::TrustEngine() : db_initialized_(false) {
  syslog(LOG_INFO, "TrustEngine oluşturuluyor...");
}

TrustEngine::~TrustEngine() { shutdown(); }

std::string TrustEngine::executeCommand(const std::string &cmd) {
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

bool TrustEngine::initialize(const std::string &db_path) {
  syslog(LOG_INFO, "TrustEngine başlatılıyor: %s", db_path.c_str());

  db_path_ = db_path;

  // Veritabanını başlat
  if (!initDatabase()) {
    syslog(LOG_ERR, "Veritabanı başlatılamadı!");
    return false;
  }

  // Mevcut uygulamaları yükle
  loadAppsFromDb();

  db_initialized_ = true;
  syslog(LOG_INFO, "TrustEngine başlatıldı (%zu uygulama)", app_cache_.size());

  return true;
}

void TrustEngine::shutdown() {
  if (!db_initialized_)
    return;

  // Tüm uygulamaları kaydet
  for (const auto &pair : app_cache_) {
    saveAppToDb(pair.second);
  }

  db_initialized_ = false;
  syslog(LOG_INFO, "TrustEngine kapatıldı");
}

bool TrustEngine::initDatabase() {
#if HAS_SQLITE3
  // Dizini oluştur
  executeCommand("mkdir -p /data/clara");

  sqlite3 *db;
  int rc = sqlite3_open(db_path_.c_str(), &db);
  if (rc != SQLITE_OK) {
    syslog(LOG_ERR, "SQLite açılamadı: %s", sqlite3_errmsg(db));
    return false;
  }

  // Tablolar oluştur
  const char *create_apps_sql = R"(
        CREATE TABLE IF NOT EXISTS app_trust (
            package_name TEXT PRIMARY KEY,
            app_name TEXT,
            install_source INTEGER,
            current_score INTEGER,
            max_achievable_score INTEGER,
            status INTEGER,
            first_seen INTEGER,
            last_violation INTEGER,
            violation_count INTEGER,
            last_good_behavior INTEGER,
            good_behavior_days INTEGER,
            is_whitelisted INTEGER,
            is_quarantined INTEGER,
            is_suspended INTEGER,
            network_blocked INTEGER
        );
    )";

  const char *create_violations_sql = R"(
        CREATE TABLE IF NOT EXISTS violation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT,
            violation_type INTEGER,
            penalty INTEGER,
            timestamp INTEGER,
            context TEXT,
            was_blocked INTEGER
        );
    )";

  char *err_msg = nullptr;
  rc = sqlite3_exec(db, create_apps_sql, nullptr, nullptr, &err_msg);
  if (rc != SQLITE_OK) {
    syslog(LOG_ERR, "Tablo oluşturulamadı: %s", err_msg);
    sqlite3_free(err_msg);
  }

  rc = sqlite3_exec(db, create_violations_sql, nullptr, nullptr, &err_msg);
  if (rc != SQLITE_OK) {
    syslog(LOG_ERR, "Violations tablo oluşturulamadı: %s", err_msg);
    sqlite3_free(err_msg);
  }

  sqlite3_close(db);
  return true;
#else
  // SQLite yoksa dosya tabanlı
  executeCommand("mkdir -p /data/clara");
  return true;
#endif
}

void TrustEngine::loadAppsFromDb() {
#if HAS_SQLITE3
  sqlite3 *db;
  if (sqlite3_open(db_path_.c_str(), &db) != SQLITE_OK) {
    return;
  }

  const char *sql = "SELECT * FROM app_trust";
  sqlite3_stmt *stmt;

  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      AppTrustInfo app;
      app.package_name =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
      app.app_name =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      app.install_source =
          static_cast<InstallSource>(sqlite3_column_int(stmt, 2));
      app.current_score = sqlite3_column_int(stmt, 3);
      app.max_achievable_score = sqlite3_column_int(stmt, 4);
      app.status = static_cast<AppStatus>(sqlite3_column_int(stmt, 5));
      app.first_seen = sqlite3_column_int64(stmt, 6);
      app.last_violation = sqlite3_column_int64(stmt, 7);
      app.violation_count = sqlite3_column_int(stmt, 8);
      app.last_good_behavior = sqlite3_column_int64(stmt, 9);
      app.good_behavior_days = sqlite3_column_int(stmt, 10);
      app.is_whitelisted = sqlite3_column_int(stmt, 11) != 0;
      app.is_quarantined = sqlite3_column_int(stmt, 12) != 0;
      app.is_suspended = sqlite3_column_int(stmt, 13) != 0;
      app.network_blocked = sqlite3_column_int(stmt, 14) != 0;

      app_cache_[app.package_name] = app;
    }
    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
#endif
}

void TrustEngine::saveAppToDb(const AppTrustInfo &app [[maybe_unused]]) {
#if HAS_SQLITE3
  sqlite3 *db;
  if (sqlite3_open(db_path_.c_str(), &db) != SQLITE_OK) {
    return;
  }

  const char *sql = R"(
        INSERT OR REPLACE INTO app_trust VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, app.package_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, app.app_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, static_cast<int>(app.install_source));
    sqlite3_bind_int(stmt, 4, app.current_score);
    sqlite3_bind_int(stmt, 5, app.max_achievable_score);
    sqlite3_bind_int(stmt, 6, static_cast<int>(app.status));
    sqlite3_bind_int64(stmt, 7, app.first_seen);
    sqlite3_bind_int64(stmt, 8, app.last_violation);
    sqlite3_bind_int(stmt, 9, app.violation_count);
    sqlite3_bind_int64(stmt, 10, app.last_good_behavior);
    sqlite3_bind_int(stmt, 11, app.good_behavior_days);
    sqlite3_bind_int(stmt, 12, app.is_whitelisted ? 1 : 0);
    sqlite3_bind_int(stmt, 13, app.is_quarantined ? 1 : 0);
    sqlite3_bind_int(stmt, 14, app.is_suspended ? 1 : 0);
    sqlite3_bind_int(stmt, 15, app.network_blocked ? 1 : 0);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
#endif
}

InstallSource
TrustEngine::detectInstallSource(const std::string &package_name) {
  // pm dump ile installer package'ı bul
  std::string cmd = "pm dump " + package_name +
                    " 2>/dev/null | grep 'installerPackageName=' | head -1";
  std::string result = executeCommand(cmd);

  // installerPackageName=com.android.vending formatından çıkar
  std::regex regex("installerPackageName=([^\\s]+)");
  std::smatch match;

  if (std::regex_search(result, match, regex)) {
    std::string installer = match[1].str();

    // Bilinen mağaza mı?
    auto it = STORE_PACKAGES.find(installer);
    if (it != STORE_PACKAGES.end()) {
      return it->second;
    }

    // null veya boş = sideload
    if (installer == "null" || installer.empty()) {
      return InstallSource::SIDELOAD;
    }
  }

  // Sistem uygulaması mı?
  std::string sys_check =
      executeCommand("pm path " + package_name + " 2>/dev/null");
  if (sys_check.find("/system/") != std::string::npos ||
      sys_check.find("/product/") != std::string::npos ||
      sys_check.find("/vendor/") != std::string::npos) {
    return InstallSource::SYSTEM;
  }

  return InstallSource::UNKNOWN;
}

int TrustEngine::getInitialScore(InstallSource source) {
  auto it = INITIAL_SCORES.find(source);
  return (it != INITIAL_SCORES.end()) ? it->second : 20;
}

int TrustEngine::getMaxScore(InstallSource source) {
  auto it = MAX_SCORES.find(source);
  return (it != MAX_SCORES.end()) ? it->second : 60;
}

AppStatus TrustEngine::calculateStatus(int score) {
  if (score >= 80)
    return AppStatus::TRUSTED;
  if (score >= 50)
    return AppStatus::NORMAL;
  if (score >= 20)
    return AppStatus::SUSPICIOUS;
  return AppStatus::QUARANTINED;
}

// =========================================================================
// Uygulama Yönetimi
// =========================================================================

AppTrustInfo TrustEngine::registerApp(const std::string &package_name) {
  // Zaten var mı?
  if (app_cache_.count(package_name) > 0) {
    return app_cache_[package_name];
  }

  AppTrustInfo app;
  app.package_name = package_name;
  app.app_name = package_name; // TODO: Gerçek ismi al
  app.install_source = detectInstallSource(package_name);
  app.current_score = getInitialScore(app.install_source);
  app.max_achievable_score = getMaxScore(app.install_source);
  app.status = calculateStatus(app.current_score);
  app.first_seen = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  app.last_violation = 0;
  app.violation_count = 0;
  app.last_good_behavior = app.first_seen;
  app.good_behavior_days = 0;
  app.is_whitelisted = false;
  app.is_quarantined = (app.status == AppStatus::QUARANTINED);
  app.is_suspended = false;
  app.network_blocked = false;

  // Sistem uygulaması
  if (app.install_source == InstallSource::SYSTEM) {
    app.status = AppStatus::SYSTEM;
    app.current_score = 100;
  }

  app_cache_[package_name] = app;
  saveAppToDb(app);

  syslog(LOG_INFO, "Uygulama kaydedildi: %s (kaynak: %d, puan: %d)",
         package_name.c_str(), static_cast<int>(app.install_source),
         app.current_score);

  return app;
}

AppTrustInfo TrustEngine::getAppInfo(const std::string &package_name) {
  if (app_cache_.count(package_name) > 0) {
    return app_cache_[package_name];
  }

  // Cache'de yok, kaydet
  return registerApp(package_name);
}

std::vector<AppTrustInfo> TrustEngine::getAllApps() {
  std::vector<AppTrustInfo> apps;
  for (const auto &pair : app_cache_) {
    apps.push_back(pair.second);
  }
  return apps;
}

std::vector<AppTrustInfo> TrustEngine::getAppsByStatus(AppStatus status) {
  std::vector<AppTrustInfo> apps;
  for (const auto &pair : app_cache_) {
    if (pair.second.status == status) {
      apps.push_back(pair.second);
    }
  }
  return apps;
}

void TrustEngine::whitelistApp(const std::string &package_name) {
  if (app_cache_.count(package_name) == 0) {
    registerApp(package_name);
  }

  app_cache_[package_name].is_whitelisted = true;

  // Karantinadan çıkar
  if (app_cache_[package_name].is_quarantined) {
    releaseFromQuarantine(package_name);
  }

  saveAppToDb(app_cache_[package_name]);
  syslog(LOG_INFO, "Whitelist'e eklendi: %s", package_name.c_str());
}

void TrustEngine::unwhitelistApp(const std::string &package_name) {
  if (app_cache_.count(package_name) > 0) {
    app_cache_[package_name].is_whitelisted = false;
    saveAppToDb(app_cache_[package_name]);
    syslog(LOG_INFO, "Whitelist'ten çıkarıldı: %s", package_name.c_str());
  }
}

// =========================================================================
// Puanlama
// =========================================================================

int TrustEngine::getScore(const std::string &package_name) {
  if (app_cache_.count(package_name) > 0) {
    return app_cache_[package_name].current_score;
  }
  return registerApp(package_name).current_score;
}

AppStatus TrustEngine::getStatus(const std::string &package_name) {
  if (app_cache_.count(package_name) > 0) {
    return app_cache_[package_name].status;
  }
  return registerApp(package_name).status;
}

void TrustEngine::recordViolation(const std::string &package_name,
                                  ViolationType type,
                                  const std::string &context) {
  if (app_cache_.count(package_name) == 0) {
    registerApp(package_name);
  }

  AppTrustInfo &app = app_cache_[package_name];

  // Whitelist kontrolü
  if (app.is_whitelisted) {
    syslog(LOG_DEBUG, "Whitelist'te, ihlal görmezden gelindi: %s",
           package_name.c_str());
    return;
  }

  // Sistem uygulaması kontrolü
  if (app.status == AppStatus::SYSTEM) {
    return;
  }

  int penalty = PenaltyMatrix::getPenalty(type);
  int old_score = app.current_score;

  // Puanı düşür (minimum 0)
  app.current_score = std::max(0, app.current_score + penalty);
  app.last_violation = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
  app.violation_count++;
  app.good_behavior_days = 0; // Seri bozuldu

  // Durumu güncelle
  app.status = calculateStatus(app.current_score);

  // İhlal kaydı
  ViolationRecord record;
  record.package_name = package_name;
  record.violation_type = type;
  record.penalty = penalty;
  record.timestamp = app.last_violation;
  record.context = context;
  record.was_blocked = false;

  saveViolationToDb(record);
  saveAppToDb(app);

  stats_.total_violations++;

  syslog(LOG_WARNING, "İhlal: %s, tip: %d, ceza: %d, yeni puan: %d",
         package_name.c_str(), static_cast<int>(type), penalty,
         app.current_score);

  // Callback
  if (violation_callback_) {
    violation_callback_(package_name, type, app.current_score);
  }

  if (score_change_callback_) {
    score_change_callback_(package_name, old_score, app.current_score);
  }

  // Enforcement uygula
  enforceByScore(package_name);
}

void TrustEngine::rewardGoodBehavior(const std::string &package_name,
                                     int bonus) {
  if (app_cache_.count(package_name) == 0) {
    return;
  }

  AppTrustInfo &app = app_cache_[package_name];

  // Sistem uygulaması ise atlat
  if (app.status == AppStatus::SYSTEM) {
    return;
  }

  int old_score = app.current_score;

  // Puanı artır (maksimum sınırına kadar)
  app.current_score =
      std::min(app.max_achievable_score, app.current_score + bonus);
  app.last_good_behavior =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  app.good_behavior_days++;

  // Durumu güncelle
  AppStatus old_status = app.status;
  app.status = calculateStatus(app.current_score);

  saveAppToDb(app);

  // Karantinadan çıkış
  if (old_status == AppStatus::QUARANTINED &&
      app.status != AppStatus::QUARANTINED) {
    releaseFromQuarantine(package_name);
  }

  if (score_change_callback_ && old_score != app.current_score) {
    score_change_callback_(package_name, old_score, app.current_score);
  }

  syslog(LOG_INFO, "İyi davranış bonusu: %s, +%d, yeni puan: %d",
         package_name.c_str(), bonus, app.current_score);
}

void TrustEngine::dailyBehaviorCheck() {
  int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();

  int64_t one_day = 24 * 60 * 60;

  for (auto &pair : app_cache_) {
    AppTrustInfo &app = pair.second;

    // Son 24 saatte ihlal olmadıysa bonus ver
    if (now - app.last_violation > one_day) {
      rewardGoodBehavior(app.package_name, 2);
    }
  }

  syslog(LOG_INFO, "Günlük davranış kontrolü tamamlandı");
}

void TrustEngine::saveViolationToDb(const ViolationRecord &record
                                    [[maybe_unused]]) {
#if HAS_SQLITE3
  sqlite3 *db;
  if (sqlite3_open(db_path_.c_str(), &db) != SQLITE_OK) {
    return;
  }

  const char *sql = R"(
        INSERT INTO violation_log (package_name, violation_type, penalty, timestamp, context, was_blocked)
        VALUES (?, ?, ?, ?, ?, ?)
    )";

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(stmt, 1, record.package_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, static_cast<int>(record.violation_type));
    sqlite3_bind_int(stmt, 3, record.penalty);
    sqlite3_bind_int64(stmt, 4, record.timestamp);
    sqlite3_bind_text(stmt, 5, record.context.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, record.was_blocked ? 1 : 0);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
#endif
}

// =========================================================================
// Install Guard
// =========================================================================

bool TrustEngine::onPackageAdded(const std::string &package_name) {
  syslog(LOG_INFO, "Yeni uygulama yüklendi: %s", package_name.c_str());

  AppTrustInfo app = registerApp(package_name);

  // Play Store dışından geldiyse karantinaya al
  if (app.install_source == InstallSource::SIDELOAD ||
      app.install_source == InstallSource::UNKNOWN ||
      app.install_source == InstallSource::ADB) {

    syslog(LOG_WARNING, "Sideload tespit edildi, karantinaya alınıyor: %s",
           package_name.c_str());
    quarantineApp(package_name);

    // Callback
    if (quarantine_callback_) {
      quarantine_callback_(package_name, true);
    }

    return true; // Karantinaya alındı
  }

  return false; // Normal yükleme
}

bool TrustEngine::quarantineApp(const std::string &package_name) {
  if (app_cache_.count(package_name) == 0) {
    registerApp(package_name);
  }

  AppTrustInfo &app = app_cache_[package_name];

  // Zaten karantinada
  if (app.is_quarantined) {
    return true;
  }

  // Whitelist kontrolü
  if (app.is_whitelisted) {
    syslog(LOG_INFO, "Whitelist'te, karantinaya alınmadı: %s",
           package_name.c_str());
    return false;
  }

  // Suspend et
  suspendApp(package_name);

  // Ağı engelle
  blockNetwork(package_name);

  app.is_quarantined = true;
  app.status = AppStatus::QUARANTINED;
  app.current_score = 0;

  saveAppToDb(app);
  stats_.quarantined_apps++;

  syslog(LOG_WARNING, "Karantinaya alındı: %s", package_name.c_str());

  return true;
}

bool TrustEngine::releaseFromQuarantine(const std::string &package_name) {
  if (app_cache_.count(package_name) == 0) {
    return false;
  }

  AppTrustInfo &app = app_cache_[package_name];

  if (!app.is_quarantined) {
    return true;
  }

  // Unsuspend
  unsuspendApp(package_name);

  // Ağı aç
  unblockNetwork(package_name);

  app.is_quarantined = false;
  app.status = calculateStatus(app.current_score);

  saveAppToDb(app);
  stats_.quarantined_apps--;

  syslog(LOG_INFO, "Karantinadan çıkarıldı: %s", package_name.c_str());

  if (quarantine_callback_) {
    quarantine_callback_(package_name, false);
  }

  return true;
}

std::vector<AppTrustInfo> TrustEngine::getQuarantinedApps() {
  return getAppsByStatus(AppStatus::QUARANTINED);
}

// =========================================================================
// Enforcement
// =========================================================================

bool TrustEngine::suspendApp(const std::string &package_name) {
  std::string cmd = "pm suspend " + package_name + " 2>/dev/null";
  executeCommand(cmd);

  if (app_cache_.count(package_name) > 0) {
    app_cache_[package_name].is_suspended = true;
    saveAppToDb(app_cache_[package_name]);
  }

  syslog(LOG_INFO, "Uygulama askıya alındı: %s", package_name.c_str());
  return true;
}

bool TrustEngine::unsuspendApp(const std::string &package_name) {
  std::string cmd = "pm unsuspend " + package_name + " 2>/dev/null";
  executeCommand(cmd);

  if (app_cache_.count(package_name) > 0) {
    app_cache_[package_name].is_suspended = false;
    saveAppToDb(app_cache_[package_name]);
  }

  syslog(LOG_INFO, "Uygulama askıdan alındı: %s", package_name.c_str());
  return true;
}

bool TrustEngine::forceStopApp(const std::string &package_name) {
  std::string cmd = "am force-stop " + package_name + " 2>/dev/null";
  executeCommand(cmd);

  syslog(LOG_INFO, "Uygulama zorla durduruldu: %s", package_name.c_str());
  return true;
}

bool TrustEngine::revokePermission(const std::string &package_name,
                                   const std::string &permission) {
  std::string cmd =
      "pm revoke " + package_name + " " + permission + " 2>/dev/null";
  executeCommand(cmd);

  syslog(LOG_INFO, "İzin geri alındı: %s -> %s", package_name.c_str(),
         permission.c_str());
  return true;
}

int TrustEngine::getAppUid(const std::string &package_name) {
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

bool TrustEngine::blockNetwork(const std::string &package_name) {
  int uid = getAppUid(package_name);
  if (uid < 0)
    return false;

  std::string cmd = "iptables -A OUTPUT -m owner --uid-owner " +
                    std::to_string(uid) + " -j DROP 2>/dev/null";
  executeCommand(cmd);

  if (app_cache_.count(package_name) > 0) {
    app_cache_[package_name].network_blocked = true;
    saveAppToDb(app_cache_[package_name]);
  }

  syslog(LOG_INFO, "Ağ engellendi: %s (UID: %d)", package_name.c_str(), uid);
  return true;
}

bool TrustEngine::unblockNetwork(const std::string &package_name) {
  int uid = getAppUid(package_name);
  if (uid < 0)
    return false;

  std::string cmd = "iptables -D OUTPUT -m owner --uid-owner " +
                    std::to_string(uid) + " -j DROP 2>/dev/null";
  executeCommand(cmd);

  if (app_cache_.count(package_name) > 0) {
    app_cache_[package_name].network_blocked = false;
    saveAppToDb(app_cache_[package_name]);
  }

  syslog(LOG_INFO, "Ağ engeli kaldırıldı: %s", package_name.c_str());
  return true;
}

void TrustEngine::enforceByScore(const std::string &package_name) {
  if (app_cache_.count(package_name) == 0) {
    return;
  }

  AppTrustInfo &app = app_cache_[package_name];
  int score = app.current_score;

  // Whitelist ise müdahale etme
  if (app.is_whitelisted) {
    return;
  }

  if (score >= 80) {
    // YEŞIL: Sadece log
    // Hiçbir enforceent yok
  } else if (score >= 50) {
    // SARI: Fuzzy Data
    sendFuzzyLocation(package_name);

    // Hassas izinleri geri al
    revokePermission(package_name, "android.permission.ACCESS_FINE_LOCATION");
  } else if (score >= 20) {
    // KIRMIZI: Block + Notify
    revokePermission(package_name, "android.permission.CAMERA");
    revokePermission(package_name, "android.permission.RECORD_AUDIO");
    revokePermission(package_name, "android.permission.READ_CONTACTS");
  } else {
    // SİYAH: Karantina
    quarantineApp(package_name);
    forceStopApp(package_name);
  }
}

// =========================================================================
// Fuzzy Data
// =========================================================================

void TrustEngine::sendFuzzyLocation(const std::string &package_name) {
  if (!fuzzy_config_.location_fuzzy)
    return;

  // Apple Park koordinatları 😄
  double lat = FuzzyDataConfig::FAKE_LATITUDE;
  double lon = FuzzyDataConfig::FAKE_LONGITUDE;

  // Mock location provider ayarla
  // NOT: Bu Android'de Settings.Secure ile yapılır
  // Gerçek implementasyonda LSPosed hook gerekebilir

  syslog(LOG_INFO, "Fuzzy location gönderildi: %s -> (%.4f, %.4f) Apple Park",
         package_name.c_str(), lat, lon);
}

FuzzyDataConfig TrustEngine::getFuzzyConfig() { return fuzzy_config_; }

void TrustEngine::setFuzzyConfig(const FuzzyDataConfig &config) {
  fuzzy_config_ = config;
}

// =========================================================================
// İstatistikler
// =========================================================================

TrustEngine::Stats TrustEngine::getStats() const { return stats_; }

std::vector<ViolationRecord>
TrustEngine::getRecentViolations(int count [[maybe_unused]]) {
  std::vector<ViolationRecord> records;

#if HAS_SQLITE3
  sqlite3 *db;
  if (sqlite3_open(db_path_.c_str(), &db) != SQLITE_OK) {
    return records;
  }

  std::string sql =
      "SELECT * FROM violation_log ORDER BY timestamp DESC LIMIT " +
      std::to_string(count);
  sqlite3_stmt *stmt;

  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      ViolationRecord r;
      r.id = sqlite3_column_int64(stmt, 0);
      r.package_name =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      r.violation_type =
          static_cast<ViolationType>(sqlite3_column_int(stmt, 2));
      r.penalty = sqlite3_column_int(stmt, 3);
      r.timestamp = sqlite3_column_int64(stmt, 4);
      r.context = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      r.was_blocked = sqlite3_column_int(stmt, 6) != 0;

      records.push_back(r);
    }
    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
#endif

  return records;
}

// =========================================================================
// Callbacks
// =========================================================================

void TrustEngine::setViolationCallback(ViolationCallback cb) {
  violation_callback_ = cb;
}

void TrustEngine::setQuarantineCallback(QuarantineCallback cb) {
  quarantine_callback_ = cb;
}

void TrustEngine::setScoreChangeCallback(ScoreChangeCallback cb) {
  score_change_callback_ = cb;
}

} // namespace clara
