/**
 * CLARA Security - File Monitor Module
 * Dosya sistemi izleme ve malware tarama
 */

#ifndef CLARA_FILE_MONITOR_H
#define CLARA_FILE_MONITOR_H

#include "clara_daemon.h"
#include <sys/inotify.h>
#include <unordered_set>

namespace clara {

/**
 * Dosya izleme modülü
 * Inotify ile gerçek zamanlı dosya izleme
 */
class FileMonitor : public IModule {
public:
  FileMonitor();
  ~FileMonitor() override;

  // IModule implementasyonu
  const std::string &getName() const override { return name_; }
  bool initialize() override;
  void start() override;
  void stop() override;
  bool isRunning() const override { return running_.load(); }
  void setEventCallback(EventCallback callback) override {
    callback_ = callback;
  }

  // Dosya işlemleri
  ThreatInfo scanFile(const std::string &path);
  void quarantineFile(const std::string &path);
  void addWatchPath(const std::string &path);
  void removeWatchPath(const std::string &path);

  // APK analiz
  ThreatInfo analyzeApk(const std::string &apk_path);
  std::vector<std::string> extractApkPermissions(const std::string &apk_path);

  // Hash işlemleri
  std::string calculateSha256(const std::string &path);
  bool isKnownMalware(const std::string &hash);

  // İstatistikler
  int getScannedCount() const { return scanned_count_.load(); }
  int getQuarantinedCount() const { return quarantined_count_.load(); }

private:
  void monitorLoop();
  void handleInotifyEvent(const inotify_event *event,
                          const std::string &base_path);
  FileInfo getFileInfo(const std::string &path);
  bool shouldScan(const std::string &path);
  void loadMalwareHashes();

  std::string name_ = "file_monitor";
  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  EventCallback callback_;

  // Inotify
  int inotify_fd_ = -1;
  std::unordered_map<int, std::string> watch_descriptors_;

  // İzlenen dizinler
  std::vector<std::string> watch_paths_;
  std::vector<std::string> scan_extensions_;

  // Malware hash veritabanı (bellek içi cache)
  std::unordered_set<std::string> malware_hashes_;

  // İstatistikler
  std::atomic<int> scanned_count_{0};
  std::atomic<int> quarantined_count_{0};

  // Ayarlar
  bool ai_enabled_ = true;
  bool auto_quarantine_ = false;
  std::string quarantine_path_ = "/data/clara/quarantine";
};

} // namespace clara

#endif // CLARA_FILE_MONITOR_H
