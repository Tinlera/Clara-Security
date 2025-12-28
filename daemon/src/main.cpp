/**
 * CLARA Security Daemon - Main Entry Point
 *
 * Bu dosya daemon'ın ana giriş noktasıdır.
 * Root yetkisiyle çalışır ve Android 15'te test edilmiştir.
 */

#include <csignal>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "../include/ai_engine.h"
#include "../include/clara_daemon.h"
#include "../include/file_monitor.h"
#include "../include/network_monitor.h"
#include "../include/sms_monitor.h"

using namespace clara;

// Global daemon instance pointer for signal handling
static ClaraDaemon *g_daemon = nullptr;

// Signal handler
void signalHandler(int signum) {
  syslog(LOG_INFO, "CLARA: Signal %d alındı, kapatılıyor...", signum);

  if (g_daemon) {
    g_daemon->shutdown();
  }

  exit(signum);
}

// Daemon moduna geçiş
bool daemonize() {
  // Fork işlemi
  pid_t pid = fork();

  if (pid < 0) {
    return false;
  }

  // Parent process çık
  if (pid > 0) {
    exit(0);
  }

  // Yeni session oluştur
  if (setsid() < 0) {
    return false;
  }

  // Signal'leri ignore et
  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  // Tekrar fork
  pid = fork();

  if (pid < 0) {
    return false;
  }

  if (pid > 0) {
    exit(0);
  }

  // Çalışma dizinini değiştir
  chdir("/");

  // umask ayarla
  umask(0);

  // Standart dosya tanımlayıcıları kapat
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  return true;
}

// Log dosyasına yaz
void logMessage(const std::string &level, const std::string &message) {
  std::ofstream log("/data/clara/logs/daemon.log", std::ios::app);
  if (log.is_open()) {
    time_t now = time(nullptr);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
             localtime(&now));
    log << "[" << timestamp << "] [" << level << "] " << message << std::endl;
    log.close();
  }

  // Syslog'a da yaz
  int priority = LOG_INFO;
  if (level == "ERROR")
    priority = LOG_ERR;
  else if (level == "WARN")
    priority = LOG_WARNING;
  else if (level == "DEBUG")
    priority = LOG_DEBUG;

  syslog(priority, "CLARA: %s", message.c_str());
}

// Dizin yapısını oluştur
void ensureDirectories() {
  const char *dirs[] = {"/data/clara", "/data/clara/logs",
                        "/data/clara/quarantine", "/data/clara/cache",
                        "/data/clara/database"};

  for (const char *dir : dirs) {
    mkdir(dir, 0755);
  }
}

// PID dosyası yaz
void writePidFile() {
  std::ofstream pid_file("/data/clara/clara_daemon.pid");
  if (pid_file.is_open()) {
    pid_file << getpid() << std::endl;
    pid_file.close();
  }
}

// Root kontrolü
bool checkRoot() { return getuid() == 0; }

// Ana event callback
void onSecurityEvent(const SecurityEvent &event) {
  std::string level_str;
  switch (event.level) {
  case ThreatLevel::NONE:
    level_str = "NONE";
    break;
  case ThreatLevel::LOW:
    level_str = "LOW";
    break;
  case ThreatLevel::MEDIUM:
    level_str = "MEDIUM";
    break;
  case ThreatLevel::HIGH:
    level_str = "HIGH";
    break;
  case ThreatLevel::CRITICAL:
    level_str = "CRITICAL";
    break;
  }

  std::string msg = "Event [" + level_str + "]: " + event.description;
  logMessage("EVENT", msg);

  // Yüksek tehditlerde bildirim gönder
  if (event.level >= ThreatLevel::HIGH) {
    // TODO: Android notification gönder
    logMessage("ALERT", "Yüksek tehdit tespit edildi: " + event.description);
  }
}

int main(int argc, char *argv[]) {
  // Syslog başlat
  openlog("clara_daemon", LOG_PID | LOG_CONS, LOG_DAEMON);

  // Root kontrolü
  if (!checkRoot()) {
    std::cerr << "HATA: CLARA Daemon root yetkisi gerektirir!" << std::endl;
    syslog(LOG_ERR, "Root yetkisi yok, çıkılıyor...");
    return 1;
  }

  // Foreground mod kontrolü
  bool foreground = false;
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "-f" ||
        std::string(argv[i]) == "--foreground") {
      foreground = true;
    }
  }

  // Daemon moduna geç (eğer foreground değilse)
  if (!foreground) {
    if (!daemonize()) {
      syslog(LOG_ERR, "Daemon moduna geçilemedi!");
      return 1;
    }
  }

  // Dizinleri oluştur
  ensureDirectories();

  // PID dosyasını yaz
  writePidFile();

  logMessage("INFO", "CLARA Security Daemon v" + std::string(VERSION) +
                         " başlatılıyor...");

  // Signal handler'ları ayarla
  signal(SIGTERM, signalHandler);
  signal(SIGINT, signalHandler);
  signal(SIGQUIT, signalHandler);

  // Daemon instance al
  ClaraDaemon &daemon = ClaraDaemon::getInstance();
  g_daemon = &daemon;

  // Konfigürasyon dosyası yolu
  std::string config_path = "/system/etc/clara/config.json";
  if (access(config_path.c_str(), R_OK) != 0) {
    config_path =
        "/data/adb/modules/clara_security/system/etc/clara/config.json";
  }

  // Daemon'ı başlat
  if (!daemon.initialize(config_path)) {
    logMessage("ERROR", "Daemon başlatılamadı!");
    return 1;
  }

  // Event callback ayarla
  daemon.setEventCallback(onSecurityEvent);

  // Modülleri kaydet
  auto sms_monitor = std::make_shared<SmsMonitor>();
  auto file_monitor = std::make_shared<FileMonitor>();
  auto network_monitor = std::make_shared<NetworkMonitor>();

  daemon.registerModule(sms_monitor);
  daemon.registerModule(file_monitor);
  daemon.registerModule(network_monitor);

  logMessage("INFO", "Tüm modüller kaydedildi");

  // Ana döngüyü çalıştır
  logMessage("INFO", "CLARA Security Daemon aktif");
  daemon.run();

  logMessage("INFO", "CLARA Security Daemon kapatıldı");
  closelog();

  return 0;
}
