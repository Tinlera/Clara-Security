/**
 * CLARA Security - Privacy Core Main Entry
 */

#include "../include/permission_watcher.h"
#include "../include/tracker_blocker.h"
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <sys/stat.h>
#include <syslog.h>
#include <thread>
#include <unistd.h>

using namespace clara;

static std::atomic<bool> g_running{true};

void signalHandler(int signum) {
  syslog(LOG_INFO, "Signal %d alındı, kapatılıyor...", signum);
  g_running = false;
}

void daemonize() {
  pid_t pid = fork();
  if (pid < 0)
    exit(1);
  if (pid > 0)
    exit(0);

  setsid();
  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  pid = fork();
  if (pid < 0)
    exit(1);
  if (pid > 0)
    exit(0);

  chdir("/");
  umask(0);

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

int main(int argc, char *argv[]) {
  openlog("clara_privacy_core", LOG_PID | LOG_CONS, LOG_DAEMON);

  if (getuid() != 0) {
    std::cerr << "HATA: Root yetkisi gerekli!" << std::endl;
    return 1;
  }

  bool foreground = false;
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "-f") {
      foreground = true;
    }
  }

  if (!foreground) {
    daemonize();
  }

  syslog(LOG_INFO, "CLARA Privacy Core v0.2.0 başlatılıyor...");

  signal(SIGTERM, signalHandler);
  signal(SIGINT, signalHandler);

  // Modülleri oluştur
  PermissionWatcher permission_watcher;
  TrackerBlocker tracker_blocker;

  // Başlat
  permission_watcher.initialize();
  tracker_blocker.initialize();

  permission_watcher.start();
  tracker_blocker.start();

  syslog(LOG_INFO, "Privacy Core çalışıyor");

  // Ana döngü
  while (g_running.load()) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  // Durdur
  permission_watcher.stop();
  tracker_blocker.stop();

  syslog(LOG_INFO, "Privacy Core kapatıldı");
  closelog();

  return 0;
}
