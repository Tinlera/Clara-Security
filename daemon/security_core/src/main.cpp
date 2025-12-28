/**
 * CLARA Security - Security Core Main Entry
 */

#include "../../include/file_monitor.h"
#include "../../include/network_monitor.h"
#include "../../include/sms_monitor.h"
#include "../include/keylogger_detector.h"
#include "../include/messenger_monitor.h"
#include <chrono>
#include <csignal>
#include <iostream>
#include <sys/stat.h>
#include <syslog.h>
#include <thread>
#include <unistd.h>

using namespace clara;

static std::atomic<bool> g_running{true};

// Global pointers for signal handler access
SmsMonitor *g_sms_monitor = nullptr;
FileMonitor *g_file_monitor = nullptr;
NetworkMonitor *g_network_monitor = nullptr;
MessengerMonitor *g_messenger_monitor = nullptr;
KeyloggerDetector *g_keylogger_detector = nullptr;

void signalHandler(int signum) {
  if (signum == SIGTERM || signum == SIGINT) {
    syslog(LOG_INFO, "Signal %d alındı, kapatılıyor...", signum);
    g_running = false;
  } else if (signum == SIGUSR1) {
    syslog(LOG_INFO, "SIGUSR1 alındı: Manuel tarama başlatılıyor...");
    // Tarama mantığı burada tetiklenecek
    // Şimdilik sadece log basalım, modüller zaten sürekli çalışıyor
    // İleride modüllere 'performScan()' metodu eklenebilir
    if (g_file_monitor) {
      // g_file_monitor->scanAllFiles(); // Örnek
    }
  }
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

// IPC Definitions
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>

const char *SOCKET_PATH = "/data/clara/security_core.sock";

void handleIpcConnection(int client_fd) {
  char buffer[1024];
  ssize_t bytes = read(client_fd, buffer, sizeof(buffer) - 1);
  if (bytes > 0) {
    buffer[bytes] = '\0';
    std::string command(buffer);
    std::string response = "UNKNOWN";

    if (command == "SCAN_ALL") {
      syslog(LOG_INFO, "IPC Komutu alındı: SCAN_ALL");
      // Tarama simülasyonu
      // Gerçekte burada tüm monitörlerin scan metodunu çağıracağız
      response = "OK";
    } else if (command == "PING") {
      response = "PONG";
    }

    write(client_fd, response.c_str(), response.length());
  }
}

void ipcThread() {
  unlink(SOCKET_PATH);
  int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd < 0) {
    syslog(LOG_ERR, "IPC Socket oluşturulamadı");
    return;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "IPC Bind hatası");
    close(server_fd);
    return;
  }

  chmod(SOCKET_PATH, 0666);
  listen(server_fd, 5);

  while (g_running.load()) {
    struct sockaddr_un client_addr;
    socklen_t len = sizeof(client_addr);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    int ret = select(server_fd + 1, &readfds, nullptr, nullptr, &tv);
    if (ret > 0 && FD_ISSET(server_fd, &readfds)) {
      int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
      if (client_fd >= 0) {
        handleIpcConnection(client_fd);
        close(client_fd);
      }
    }
  }
  close(server_fd);
  unlink(SOCKET_PATH);
}

int main(int argc, char *argv[]) {
  openlog("clara_security_core", LOG_PID | LOG_CONS, LOG_DAEMON);

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

  syslog(LOG_INFO, "CLARA Security Core v0.2.0 başlatılıyor...");

  signal(SIGTERM, signalHandler);
  signal(SIGINT, signalHandler);
  signal(SIGUSR1, signalHandler);

  // Modülleri oluştur
  SmsMonitor sms_monitor;
  FileMonitor file_monitor;
  NetworkMonitor network_monitor;
  MessengerMonitor messenger_monitor;
  KeyloggerDetector keylogger_detector;

  g_sms_monitor = &sms_monitor;
  g_file_monitor = &file_monitor;
  g_network_monitor = &network_monitor;
  g_messenger_monitor = &messenger_monitor;
  g_keylogger_detector = &keylogger_detector;

  // Başlat
  sms_monitor.initialize();
  file_monitor.initialize();
  network_monitor.initialize();
  messenger_monitor.initialize();
  keylogger_detector.initialize();

  sms_monitor.start();
  file_monitor.start();
  network_monitor.start();
  messenger_monitor.start();
  keylogger_detector.start();

  // IPC Thread Başlat
  std::thread ipc_t(ipcThread);

  syslog(LOG_INFO, "Security Core çalışıyor");

  // Ana döngü
  while (g_running.load()) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  // Durdur
  sms_monitor.stop();
  file_monitor.stop();
  network_monitor.stop();
  messenger_monitor.stop();
  keylogger_detector.stop();

  if (ipc_t.joinable())
    ipc_t.join();

  syslog(LOG_INFO, "Security Core kapatıldı");
  closelog();

  return 0;
}
