/**
 * CLARA Security - Overlay Attack Detector
 *
 * SYSTEM_ALERT_WINDOW izni kullanan ve ekran üzerine
 * çizim yapan şüpheli uygulamaları tespit eder.
 *
 * Banking trojan'lar bu tekniği kullanarak sahte
 * login ekranları gösterir.
 */

#ifndef CLARA_OVERLAY_DETECTOR_H
#define CLARA_OVERLAY_DETECTOR_H

#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clara {

/**
 * Overlay uygulama bilgisi
 */
struct OverlayAppInfo {
  std::string package_name;
  std::string app_name;
  bool has_overlay_permission; // SYSTEM_ALERT_WINDOW izni var mı
  bool is_currently_drawing;   // Şu an çizim yapıyor mu
  bool is_system_app;          // Sistem uygulaması mı
  bool is_whitelisted;         // Kullanıcı tarafından izin verilmiş mi
  int overlay_count;           // Kaç kez overlay açtı
  int64_t last_overlay_time;   // Son overlay zamanı
  std::string overlay_type;    // "toast", "alert", "fullscreen", etc.
};

/**
 * Overlay tehdit seviyesi
 */
enum class OverlayThreatLevel {
  SAFE,    // Bilinen güvenli (sistem, whitelist)
  LOW,     // Sadece izin var, aktif değil
  MEDIUM,  // Overlay aktif ama tam ekran değil
  HIGH,    // Tam ekran overlay
  CRITICAL // Hassas uygulama üzerinde overlay
};

/**
 * Hassas uygulama kategorileri (overlay'e karşı korunacak)
 */
enum class SensitiveAppCategory {
  BANKING,       // Banka uygulamaları
  PAYMENT,       // Ödeme uygulamaları
  PASSWORD,      // Şifre yöneticileri
  AUTHENTICATOR, // 2FA uygulamaları
  CRYPTO,        // Kripto cüzdanları
  EMAIL,         // E-posta
  SOCIAL,        // Sosyal medya login
  OTHER
};

/**
 * Overlay Attack Detector sınıfı
 */
class OverlayDetector {
public:
  OverlayDetector();
  ~OverlayDetector();

  /**
   * Detector'ı başlat
   * @return Başarılı ise true
   */
  bool initialize();

  /**
   * Detector'ı durdur
   */
  void stop();

  /**
   * Tek seferlik tarama yap
   * @return Tespit edilen şüpheli overlay sayısı
   */
  int scan();

  /**
   * Sürekli izleme başlat
   * @param interval_ms Tarama aralığı (ms)
   */
  void startMonitoring(int interval_ms = 1000);

  /**
   * SYSTEM_ALERT_WINDOW izni olan tüm uygulamaları al
   */
  std::vector<OverlayAppInfo> getOverlayApps();

  /**
   * Şu an aktif overlay olan uygulamaları al
   */
  std::vector<OverlayAppInfo> getActiveOverlays();

  /**
   * Belirli bir uygulamanın overlay iznini kontrol et
   */
  bool hasOverlayPermission(const std::string &package_name);

  /**
   * Ön plandaki uygulamayı al
   */
  std::string getForegroundApp();

  /**
   * Ön plandaki uygulama hassas mı?
   */
  bool isSensitiveApp(const std::string &package_name);

  /**
   * Uygulamayı whitelist'e ekle
   */
  void addToWhitelist(const std::string &package_name);

  /**
   * Uygulamayı whitelist'ten çıkar
   */
  void removeFromWhitelist(const std::string &package_name);

  /**
   * Tehdit callback'i ayarla
   */
  using ThreatCallback =
      std::function<void(const OverlayAppInfo &, OverlayThreatLevel)>;
  void setThreatCallback(ThreatCallback callback);

  /**
   * Overlay iznini zorla kapat (root gerekir)
   */
  bool revokeOverlayPermission(const std::string &package_name);

  /**
   * İstatistikler
   */
  struct Stats {
    int total_overlay_apps;
    int active_overlays;
    int blocked_count;
    int whitelisted_count;
    int64_t last_scan_time;
  };
  Stats getStats() const;

private:
  bool running_;
  std::thread monitor_thread_;
  ThreatCallback threat_callback_;

  // Whitelist
  std::unordered_set<std::string> whitelist_;

  // Hassas uygulama paketleri
  std::unordered_map<std::string, SensitiveAppCategory> sensitive_apps_;

  // Overlay geçmişi
  std::unordered_map<std::string, OverlayAppInfo> overlay_history_;

  // İstatistikler
  Stats stats_;

  // Yardımcı fonksiyonlar
  void loadWhitelist();
  void saveWhitelist();
  void loadSensitiveApps();
  std::string executeCommand(const std::string &cmd);
  void checkOverlays();
  OverlayThreatLevel assessThreat(const OverlayAppInfo &app);
  void monitorLoop(int interval_ms);
};

} // namespace clara

#endif // CLARA_OVERLAY_DETECTOR_H
