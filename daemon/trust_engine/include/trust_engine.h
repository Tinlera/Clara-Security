/**
 * CLARA Security - Trust Engine
 *
 * Dinamik güven puanı sistemi. Her uygulama için 0-100 arası
 * bir güven puanı tutar ve davranışlarına göre günceller.
 *
 * Features:
 * - Install Guard: Play Store dışı yüklemeleri karantina
 * - Behavior Monitor: İzin kullanımı izleme
 * - Rehabilitation: İyi davranış bonusu
 * - Fuzzy Data: Sahte konum/veri gönderme
 * - Enforcement: pm revoke, suspend, iptables
 */

#ifndef CLARA_TRUST_ENGINE_H
#define CLARA_TRUST_ENGINE_H

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace clara {

/**
 * Uygulama durumu
 */
enum class AppStatus {
  TRUSTED,     // Güvenilir (80-100)
  NORMAL,      // Normal (50-79)
  SUSPICIOUS,  // Şüpheli (20-49)
  QUARANTINED, // Karantinada (0-19)
  SYSTEM       // Sistem uygulaması (puanlanmaz)
};

/**
 * Yükleme kaynağı
 */
enum class InstallSource {
  PLAY_STORE,   // com.android.vending
  GALAXY_STORE, // com.sec.android.app.samsungapps
  XIAOMI_STORE, // com.xiaomi.mipicks
  HUAWEI_STORE, // com.huawei.appmarket
  AMAZON_STORE, // com.amazon.venezia
  FDROID,       // org.fdroid.fdroid
  SIDELOAD,     // Bilinmeyen/APK kurulum
  ADB,          // adb install
  SYSTEM,       // Sistem uygulaması
  UNKNOWN
};

/**
 * İhlal tipi
 */
enum class ViolationType {
  // Kritik (-30 puan)
  HIDDEN_CAMERA,       // Gizli kamera kullanımı
  HIDDEN_MICROPHONE,   // Gizli mikrofon kullanımı
  ACCESSIBILITY_ABUSE, // Accessibility kötüye kullanım

  // Yüksek (-20 puan)
  GALLERY_SCAN,   // Galeri tarama
  FILE_SCAN,      // Dosya sistemi tarama
  CONTACT_EXPORT, // Rehber dışa aktarma
  SMS_READ,       // SMS okuma

  // Orta (-15 puan)
  CLIPBOARD_SNOOP,   // Pano izleme
  NOTIFICATION_READ, // Bildirim okuma
  CALL_LOG_ACCESS,   // Arama kaydı erişimi

  // Düşük (-10 puan)
  BACKGROUND_LOCATION, // Arka plan konum
  BATTERY_DRAIN,       // Aşırı pil tüketimi
  DATA_USAGE_HIGH,     // Yüksek veri kullanımı

  // Minimal (-5 puan)
  OVERLAY_USAGE, // Overlay kullanımı
  BOOT_START     // Açılışta başlama
};

/**
 * Ceza matrisi
 */
struct PenaltyMatrix {
  static int getPenalty(ViolationType type) {
    switch (type) {
    case ViolationType::HIDDEN_CAMERA:
    case ViolationType::HIDDEN_MICROPHONE:
    case ViolationType::ACCESSIBILITY_ABUSE:
      return -30;

    case ViolationType::GALLERY_SCAN:
    case ViolationType::FILE_SCAN:
    case ViolationType::CONTACT_EXPORT:
    case ViolationType::SMS_READ:
      return -20;

    case ViolationType::CLIPBOARD_SNOOP:
    case ViolationType::NOTIFICATION_READ:
    case ViolationType::CALL_LOG_ACCESS:
      return -15;

    case ViolationType::BACKGROUND_LOCATION:
    case ViolationType::BATTERY_DRAIN:
    case ViolationType::DATA_USAGE_HIGH:
      return -10;

    case ViolationType::OVERLAY_USAGE:
    case ViolationType::BOOT_START:
      return -5;

    default:
      return -5;
    }
  }
};

/**
 * Uygulama güven bilgisi
 */
struct AppTrustInfo {
  std::string package_name;
  std::string app_name;
  InstallSource install_source;
  int current_score;        // 0-100
  int max_achievable_score; // Kaynak bazlı maksimum
  AppStatus status;
  int64_t first_seen;         // İlk görülme zamanı
  int64_t last_violation;     // Son ihlal zamanı
  int violation_count;        // Toplam ihlal sayısı
  int64_t last_good_behavior; // Son iyi davranış zamanı
  int good_behavior_days;     // Ardışık iyi gün sayısı
  bool is_whitelisted;        // Kullanıcı güveniyor
  bool is_quarantined;        // Karantinada mı
  bool is_suspended;          // Askıya alındı mı
  bool network_blocked;       // Ağ engellendi mi
};

/**
 * İhlal kaydı
 */
struct ViolationRecord {
  int64_t id;
  std::string package_name;
  ViolationType violation_type;
  int penalty;
  int64_t timestamp;
  std::string context; // Ek bilgi (örn: hangi dosya tarandı)
  bool was_blocked;    // Engellendi mi
};

/**
 * Fuzzy Data ayarları
 */
struct FuzzyDataConfig {
  // Apple Park koordinatları 😄
  static constexpr double FAKE_LATITUDE = 37.3349;
  static constexpr double FAKE_LONGITUDE = -122.0090;

  bool location_fuzzy = true;  // Sahte konum gönder
  bool contacts_fuzzy = true;  // Sahte rehber
  bool device_id_fuzzy = true; // Sahte cihaz ID
};

/**
 * Trust Engine sınıfı
 */
class TrustEngine {
public:
  TrustEngine();
  ~TrustEngine();

  /**
   * Engine'i başlat
   */
  bool initialize(const std::string &db_path = "/data/clara/trust.db");

  /**
   * Engine'i durdur ve veritabanını kaydet
   */
  void shutdown();

  // =========================================================================
  // Uygulama Yönetimi
  // =========================================================================

  /**
   * Yeni uygulama kaydı (yükleme sırasında çağrılır)
   */
  AppTrustInfo registerApp(const std::string &package_name);

  /**
   * Uygulama bilgisini al
   */
  AppTrustInfo getAppInfo(const std::string &package_name);

  /**
   * Tüm uygulamaları al
   */
  std::vector<AppTrustInfo> getAllApps();

  /**
   * Belirli durumdaki uygulamaları al
   */
  std::vector<AppTrustInfo> getAppsByStatus(AppStatus status);

  /**
   * Uygulamayı whitelist'e ekle
   */
  void whitelistApp(const std::string &package_name);

  /**
   * Uygulamayı whitelist'ten çıkar
   */
  void unwhitelistApp(const std::string &package_name);

  // =========================================================================
  // Puanlama
  // =========================================================================

  /**
   * Uygulama puanını al
   */
  int getScore(const std::string &package_name);

  /**
   * Uygulama durumunu al
   */
  AppStatus getStatus(const std::string &package_name);

  /**
   * İhlal kaydet ve puan düşür
   */
  void recordViolation(const std::string &package_name, ViolationType type,
                       const std::string &context = "");

  /**
   * İyi davranış bonusu ver
   */
  void rewardGoodBehavior(const std::string &package_name, int bonus = 2);

  /**
   * Tüm uygulamaların günlük iyi davranış kontrolü
   */
  void dailyBehaviorCheck();

  // =========================================================================
  // Install Guard
  // =========================================================================

  /**
   * Yeni yükleme kontrolü (package added broadcast)
   */
  bool onPackageAdded(const std::string &package_name);

  /**
   * Uygulamayı karantinaya al
   */
  bool quarantineApp(const std::string &package_name);

  /**
   * Karantinadan çıkar
   */
  bool releaseFromQuarantine(const std::string &package_name);

  /**
   * Karantinadaki uygulamaları al
   */
  std::vector<AppTrustInfo> getQuarantinedApps();

  // =========================================================================
  // Enforcement
  // =========================================================================

  /**
   * Uygulamayı askıya al (pm suspend)
   */
  bool suspendApp(const std::string &package_name);

  /**
   * Askıyı kaldır (pm unsuspend)
   */
  bool unsuspendApp(const std::string &package_name);

  /**
   * Uygulamayı zorla durdur (am force-stop)
   */
  bool forceStopApp(const std::string &package_name);

  /**
   * İzni geri al (pm revoke)
   */
  bool revokePermission(const std::string &package_name,
                        const std::string &permission);

  /**
   * Ağ erişimini engelle (iptables)
   */
  bool blockNetwork(const std::string &package_name);

  /**
   * Ağ engelini kaldır
   */
  bool unblockNetwork(const std::string &package_name);

  /**
   * Puan bazlı enforcement uygula
   */
  void enforceByScore(const std::string &package_name);

  // =========================================================================
  // Fuzzy Data
  // =========================================================================

  /**
   * Sahte konum gönder (Apple Park 😄)
   */
  void sendFuzzyLocation(const std::string &package_name);

  /**
   * Fuzzy data ayarlarını al/set
   */
  FuzzyDataConfig getFuzzyConfig();
  void setFuzzyConfig(const FuzzyDataConfig &config);

  // =========================================================================
  // İstatistikler
  // =========================================================================

  struct Stats {
    int total_apps;
    int trusted_apps;
    int suspicious_apps;
    int quarantined_apps;
    int total_violations;
    int blocked_violations;
    int64_t last_scan_time;
  };
  Stats getStats() const;

  /**
   * Son ihlalleri al
   */
  std::vector<ViolationRecord> getRecentViolations(int count = 50);

  // =========================================================================
  // Callbacks
  // =========================================================================

  using ViolationCallback =
      std::function<void(const std::string &, ViolationType, int)>;
  using QuarantineCallback = std::function<void(const std::string &, bool)>;
  using ScoreChangeCallback =
      std::function<void(const std::string &, int, int)>;

  void setViolationCallback(ViolationCallback cb);
  void setQuarantineCallback(QuarantineCallback cb);
  void setScoreChangeCallback(ScoreChangeCallback cb);

private:
  bool db_initialized_;
  std::string db_path_;
  FuzzyDataConfig fuzzy_config_;
  Stats stats_;

  // Callbacks
  ViolationCallback violation_callback_;
  QuarantineCallback quarantine_callback_;
  ScoreChangeCallback score_change_callback_;

  // App cache
  std::unordered_map<std::string, AppTrustInfo> app_cache_;

  // Yardımcı fonksiyonlar
  bool initDatabase();
  void loadAppsFromDb();
  void saveAppToDb(const AppTrustInfo &app);
  void saveViolationToDb(const ViolationRecord &record);

  InstallSource detectInstallSource(const std::string &package_name);
  int getInitialScore(InstallSource source);
  int getMaxScore(InstallSource source);
  AppStatus calculateStatus(int score);

  std::string executeCommand(const std::string &cmd);
  int getAppUid(const std::string &package_name);
};

} // namespace clara

#endif // CLARA_TRUST_ENGINE_H
