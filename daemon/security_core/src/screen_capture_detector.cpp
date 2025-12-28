/**
 * CLARA Security - Screen Capture Detector Implementation
 */

#include "../include/screen_capture_detector.h"
#include <algorithm>
#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

namespace clara {

// Hassas uygulama listesi
static const std::vector<std::string> DEFAULT_SENSITIVE_APPS = {
    // CLARA kendisi
    "com.clara.security",

    // Türk Bankaları
    "com.garanti.cepsubesi",
    "com.akbank.android.apps.akbank_direkt",
    "com.ykb.android",
    "com.vakifbank.mobile",
    "com.ziraat.ziraatmobil",
    "tr.com.sekerbilisim.mbanking",
    "com.finansbank.mobile.cepsube",
    "com.teb",
    "com.ingbanktr.ingmobil",
    "com.denizbank.mobildeniz",
    "com.kuveytturk.mobil",

    // Ödeme
    "com.google.android.apps.walletnfcrel",
    "com.paypal.android.p2pmobile",
    "com.papara.app",

    // Kripto
    "com.coinbase.android",
    "com.binance.dev",
    "io.metamask",
    "com.btcturk",
    "com.paribu.app",

    // Şifre yöneticileri
    "com.lastpass.lpandroid",
    "com.x8bit.bitwarden",
    "com.agilebits.onepassword",

    // 2FA
    "com.google.android.apps.authenticator2",
    "com.authy.authy",
    "com.microsoft.msa.authenticator",
};

// Screenshot klasörleri
static const std::vector<std::string> SCREENSHOT_DIRS = {
    "/storage/emulated/0/Pictures/Screenshots",
    "/storage/emulated/0/DCIM/Screenshots",
    "/sdcard/Pictures/Screenshots",
    "/sdcard/DCIM/Screenshots",
    "/data/media/0/Pictures/Screenshots",
    "/storage/emulated/0/Movies", // Screen recording
};

ScreenCaptureDetector::ScreenCaptureDetector()
    : running_(false), last_file_check_(0) {

  syslog(LOG_INFO, "ScreenCaptureDetector oluşturuluyor...");
  screenshot_dirs_ = SCREENSHOT_DIRS;
}

ScreenCaptureDetector::~ScreenCaptureDetector() { stop(); }

bool ScreenCaptureDetector::initialize() {
  syslog(LOG_INFO, "ScreenCaptureDetector başlatılıyor...");

  loadSensitiveApps();

  // Mevcut dosyaları indexle (bunları atla)
  for (const auto &dir : screenshot_dirs_) {
    DIR *d = opendir(dir.c_str());
    if (d) {
      struct dirent *entry;
      while ((entry = readdir(d)) != nullptr) {
        if (entry->d_type == DT_REG) {
          known_files_.insert(dir + "/" + entry->d_name);
        }
      }
      closedir(d);
    }
  }

  last_file_check_ = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

  return true;
}

void ScreenCaptureDetector::stop() {
  running_ = false;
  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }
  if (inotify_thread_.joinable()) {
    inotify_thread_.join();
  }
  syslog(LOG_INFO, "ScreenCaptureDetector durduruldu");
}

std::string ScreenCaptureDetector::executeCommand(const std::string &cmd) {
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

void ScreenCaptureDetector::startMonitoring() {
  if (running_)
    return;

  running_ = true;

  // Ana izleme thread'i
  monitor_thread_ = std::thread(&ScreenCaptureDetector::monitorLoop, this);

  // inotify thread'i (dosya değişiklikleri için)
  inotify_thread_ = std::thread(&ScreenCaptureDetector::inotifyLoop, this);

  syslog(LOG_INFO, "Screen capture izleme başlatıldı");
}

void ScreenCaptureDetector::monitorLoop() {
  while (running_) {
    // MediaProjection kontrolü (ekran kaydı)
    checkMediaProjection();

    // 2 saniyede bir
    std::this_thread::sleep_for(std::chrono::seconds(2));
  }
}

void ScreenCaptureDetector::inotifyLoop() {
  int fd = inotify_init();
  if (fd < 0) {
    syslog(LOG_ERR, "inotify_init başarısız");
    return;
  }

  // Klasörleri izlemeye ekle
  std::vector<int> watch_descriptors;
  for (const auto &dir : screenshot_dirs_) {
    int wd = inotify_add_watch(fd, dir.c_str(), IN_CREATE | IN_MOVED_TO);
    if (wd >= 0) {
      watch_descriptors.push_back(wd);
      syslog(LOG_DEBUG, "inotify izleme eklendi: %s", dir.c_str());
    }
  }

  char buffer[4096];
  while (running_) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ret = select(fd + 1, &fds, nullptr, nullptr, &timeout);
    if (ret > 0 && FD_ISSET(fd, &fds)) {
      ssize_t len = read(fd, buffer, sizeof(buffer));
      if (len > 0) {
        char *ptr = buffer;
        while (ptr < buffer + len) {
          struct inotify_event *event = (struct inotify_event *)ptr;

          if (event->len > 0) {
            std::string filename(event->name);

            // Screenshot veya screen recording dosyası mı?
            if (filename.find(".png") != std::string::npos ||
                filename.find(".jpg") != std::string::npos ||
                filename.find(".mp4") != std::string::npos ||
                filename.find(".webm") != std::string::npos) {

              // Klasörü bul
              std::string dir;
              for (size_t i = 0; i < watch_descriptors.size(); i++) {
                if (watch_descriptors[i] == event->wd) {
                  dir = screenshot_dirs_[i];
                  break;
                }
              }

              std::string full_path = dir + "/" + filename;

              // Yeni dosya mı?
              if (known_files_.find(full_path) == known_files_.end()) {
                known_files_.insert(full_path);

                bool is_video = (filename.find(".mp4") != std::string::npos ||
                                 filename.find(".webm") != std::string::npos);

                ScreenCaptureEvent capture_event;
                capture_event.timestamp =
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
                capture_event.type = is_video ? CaptureType::SCREEN_RECORDING
                                              : CaptureType::SCREENSHOT;
                capture_event.file_path = full_path;
                capture_event.foreground_app = getForegroundApp();
                capture_event.was_sensitive_app = isSensitiveAppForeground();
                capture_event.was_blocked = false;

                if (is_video) {
                  stats_.recordings_detected++;
                } else {
                  stats_.screenshots_detected++;
                }
                stats_.last_detection_time = capture_event.timestamp;

                event_history_.push_back(capture_event);
                if (event_history_.size() > 100) {
                  event_history_.erase(event_history_.begin());
                }

                if (capture_event.was_sensitive_app) {
                  syslog(LOG_WARNING,
                         "HASSAS UYGULAMA ekran görüntüsü alındı! App: %s, "
                         "File: %s",
                         capture_event.foreground_app.c_str(),
                         filename.c_str());
                } else {
                  syslog(LOG_INFO, "Ekran görüntüsü tespit edildi: %s",
                         filename.c_str());
                }

                if (callback_) {
                  callback_(capture_event);
                }
              }
            }
          }

          ptr += sizeof(struct inotify_event) + event->len;
        }
      }
    }
  }

  // Temizlik
  for (int wd : watch_descriptors) {
    inotify_rm_watch(fd, wd);
  }
  close(fd);
}

void ScreenCaptureDetector::checkMediaProjection() {
  // MediaProjection (ekran kaydı) aktif mi?
  std::string result = executeCommand("dumpsys media_projection 2>/dev/null | "
                                      "grep -E 'mProjectionGrant|running'");

  bool recording_active =
      (result.find("running") != std::string::npos ||
       result.find("mProjectionGrant") != std::string::npos);

  static bool was_recording = false;

  if (recording_active && !was_recording) {
    // Kayıt başladı
    ScreenCaptureEvent event;
    event.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    event.type = CaptureType::MEDIA_PROJECTION;
    event.foreground_app = getForegroundApp();
    event.was_sensitive_app = isSensitiveAppForeground();
    event.was_blocked = false;

    stats_.recordings_detected++;
    stats_.last_detection_time = event.timestamp;

    event_history_.push_back(event);

    syslog(LOG_WARNING, "Ekran kaydı başladı! Ön plandaki app: %s",
           event.foreground_app.c_str());

    if (callback_) {
      callback_(event);
    }
  }

  was_recording = recording_active;
}

bool ScreenCaptureDetector::isScreenRecordingActive() {
  std::string result = executeCommand("dumpsys media_projection 2>/dev/null");
  return result.find("mProjectionGrant") != std::string::npos;
}

std::vector<std::string>
ScreenCaptureDetector::getRecentScreenshots(int minutes) {
  std::vector<std::string> recent;

  int64_t cutoff = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count() -
                   (minutes * 60);

  for (const auto &dir : screenshot_dirs_) {
    DIR *d = opendir(dir.c_str());
    if (d) {
      struct dirent *entry;
      while ((entry = readdir(d)) != nullptr) {
        if (entry->d_type == DT_REG) {
          std::string path = dir + "/" + entry->d_name;

          struct stat st;
          if (stat(path.c_str(), &st) == 0) {
            if (st.st_mtime >= cutoff) {
              recent.push_back(path);
            }
          }
        }
      }
      closedir(d);
    }
  }

  return recent;
}

bool ScreenCaptureDetector::isSensitiveAppForeground() {
  std::string fg = getForegroundApp();
  return sensitive_apps_.count(fg) > 0;
}

std::string ScreenCaptureDetector::getForegroundApp() {
  std::string result = executeCommand("dumpsys activity activities 2>/dev/null "
                                      "| grep 'mResumedActivity' | head -1");

  // u0 com.example/Activity formatından package adını çıkar
  size_t pos = result.find("u0 ");
  if (pos != std::string::npos) {
    std::string rest = result.substr(pos + 3);
    size_t slash = rest.find('/');
    if (slash != std::string::npos) {
      return rest.substr(0, slash);
    }
  }

  return "";
}

void ScreenCaptureDetector::setCaptureCallback(CaptureCallback callback) {
  callback_ = callback;
}

void ScreenCaptureDetector::addSensitiveApp(const std::string &package_name) {
  sensitive_apps_.insert(package_name);
  syslog(LOG_INFO, "Hassas uygulama eklendi: %s", package_name.c_str());
}

std::vector<ScreenCaptureEvent>
ScreenCaptureDetector::getRecentEvents(int count) {
  int start = std::max(0, (int)event_history_.size() - count);
  return std::vector<ScreenCaptureEvent>(event_history_.begin() + start,
                                         event_history_.end());
}

ScreenCaptureDetector::Stats ScreenCaptureDetector::getStats() const {
  return stats_;
}

void ScreenCaptureDetector::loadSensitiveApps() {
  for (const auto &app : DEFAULT_SENSITIVE_APPS) {
    sensitive_apps_.insert(app);
  }

  // Kullanıcı listesi (dosyadan)
  std::ifstream file("/data/clara/config/sensitive_apps.txt");
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line[0] != '#') {
      sensitive_apps_.insert(line);
    }
  }

  syslog(LOG_INFO, "%zu hassas uygulama yüklendi", sensitive_apps_.size());
}

} // namespace clara
