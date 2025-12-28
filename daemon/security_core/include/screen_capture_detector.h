/**
 * CLARA Security - Screen Capture Detector
 *
 * Ekran görüntüsü ve ekran kaydı almayı tespit eder.
 * Hassas uygulamalar açıkken kullanıcıyı uyarır.
 */

#ifndef CLARA_SCREEN_CAPTURE_DETECTOR_H
#define CLARA_SCREEN_CAPTURE_DETECTOR_H

#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace clara {

/**
 * Ekran yakalama tipi
 */
enum class CaptureType {
  SCREENSHOT,       // Tek ekran görüntüsü
  SCREEN_RECORDING, // Ekran kaydı
  MEDIA_PROJECTION, // MediaProjection API
  UNKNOWN
};

/**
 * Ekran yakalama olayı
 */
struct ScreenCaptureEvent {
  int64_t timestamp;
  CaptureType type;
  std::string file_path;        // Screenshot dosya yolu (varsa)
  std::string capturer_package; // Yakalayan uygulama
  std::string foreground_app;   // O an ön plandaki uygulama
  bool was_sensitive_app;       // Hassas uygulama açık mıydı
  bool was_blocked;             // Engellendi mi
};

/**
 * Screen Capture Detector sınıfı
 */
class ScreenCaptureDetector {
public:
  ScreenCaptureDetector();
  ~ScreenCaptureDetector();

  /**
   * Detector'ı başlat
   */
  bool initialize();

  /**
   * Detector'ı durdur
   */
  void stop();

  /**
   * Sürekli izleme başlat
   */
  void startMonitoring();

  /**
   * Aktif MediaProjection var mı?
   */
  bool isScreenRecordingActive();

  /**
   * Screenshot klasörlerini kontrol et
   */
  std::vector<std::string> getRecentScreenshots(int minutes = 5);

  /**
   * Hassas uygulama ön planda mı?
   */
  bool isSensitiveAppForeground();

  /**
   * Ön plandaki uygulamayı al
   */
  std::string getForegroundApp();

  /**
   * Olaylar için callback
   */
  using CaptureCallback = std::function<void(const ScreenCaptureEvent &)>;
  void setCaptureCallback(CaptureCallback callback);

  /**
   * Hassas uygulama listesine ekle
   */
  void addSensitiveApp(const std::string &package_name);

  /**
   * Son olayları al
   */
  std::vector<ScreenCaptureEvent> getRecentEvents(int count = 20);

  /**
   * İstatistikler
   */
  struct Stats {
    int screenshots_detected;
    int recordings_detected;
    int blocked_count;
    int64_t last_detection_time;
  };
  Stats getStats() const;

private:
  bool running_;
  std::thread monitor_thread_;
  std::thread inotify_thread_;
  CaptureCallback callback_;

  // Hassas uygulamalar
  std::unordered_set<std::string> sensitive_apps_;

  // Screenshot klasörleri
  std::vector<std::string> screenshot_dirs_;

  // Olay geçmişi
  std::vector<ScreenCaptureEvent> event_history_;

  // Son kontrol edilen dosyalar
  std::unordered_set<std::string> known_files_;
  int64_t last_file_check_;

  Stats stats_;

  // Yardımcı fonksiyonlar
  void monitorLoop();
  void inotifyLoop();
  void checkMediaProjection();
  void checkScreenshots();
  void loadSensitiveApps();
  std::string executeCommand(const std::string &cmd);
};

} // namespace clara

#endif // CLARA_SCREEN_CAPTURE_DETECTOR_H
