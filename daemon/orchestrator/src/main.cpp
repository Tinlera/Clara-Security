/**
 * CLARA Security - Orchestrator Main Entry
 */

#include "../include/orchestrator.h"
#include <csignal>
#include <iostream>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

using namespace clara;

static Orchestrator *g_orchestrator = nullptr;

void signalHandler(int signum) {
  syslog(LOG_INFO, "Signal %d alındı, kapatılıyor...", signum);

  if (g_orchestrator) {
    g_orchestrator->shutdown();
  }

  exit(signum);
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
  openlog("clara_orchestrator", LOG_PID | LOG_CONS, LOG_DAEMON);

  // Root kontrolü
  if (getuid() != 0) {
    std::cerr << "HATA: Root yetkisi gerekli!" << std::endl;
    return 1;
  }

  // Foreground kontrolü
  bool foreground = false;
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "-f" ||
        std::string(argv[i]) == "--foreground") {
      foreground = true;
    }
  }

  if (!foreground) {
    daemonize();
  }

  syslog(LOG_INFO, "CLARA Orchestrator v0.2.0 başlatılıyor...");

  // Signal handler
  signal(SIGTERM, signalHandler);
  signal(SIGINT, signalHandler);
  signal(SIGQUIT, signalHandler);

  // Orchestrator başlat
  Orchestrator &orch = Orchestrator::getInstance();
  g_orchestrator = &orch;

  std::string config_path = "/data/clara/config/config.json";
  if (access(config_path.c_str(), R_OK) != 0) {
    config_path = "/system/etc/clara/config.json";
  }

  if (!orch.initialize(config_path)) {
    syslog(LOG_ERR, "Orchestrator başlatılamadı!");
    return 1;
  }

  syslog(LOG_INFO, "Orchestrator çalışıyor");
  orch.run();

  syslog(LOG_INFO, "Orchestrator kapatıldı");
  closelog();

  return 0;
}
