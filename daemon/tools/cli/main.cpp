/**
 * CLARA Security CLI Tool
 * Komut satırından daemon'ları kontrol et
 */

#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

const char *SOCKET_PATH = "/data/clara/orchestrator.sock";

void printUsage(const char *program) {
  std::cout << "CLARA Security CLI v0.2.0\n\n";
  std::cout << "Kullanım: " << program << " <komut> [argümanlar]\n\n";
  std::cout << "Komutlar:\n";
  std::cout << "  status              Genel durum bilgisi\n";
  std::cout << "  services            Servis listesi\n";
  std::cout << "  start <servis>      Servisi başlat\n";
  std::cout << "  stop <servis>       Servisi durdur\n";
  std::cout << "  restart <servis>    Servisi yeniden başlat\n";
  std::cout << "  scan                Manuel tarama başlat\n";
  std::cout << "  threats             Son tehditler\n";
  std::cout << "  trackers            Engellenen tracker istatistikleri\n";
  std::cout << "  lock <paket>        Uygulamayı kilitle\n";
  std::cout << "  unlock <paket>      Uygulama kilidini aç\n";
  std::cout << "  hide <paket>        Root'u uygulamadan gizle\n";
  std::cout << "  unhide <paket>      Root gizlemeyi kaldır\n";
  std::cout << "  help                Bu yardım mesajını göster\n";
}

std::string sendCommand(const std::string &command) {
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    return "HATA: Socket oluşturulamadı";
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sock);
    return "HATA: Orchestrator'a bağlanılamadı. Daemon çalışıyor mu?";
  }

  // Komutu gönder
  write(sock, command.c_str(), command.length());

  // Yanıtı oku
  char buffer[4096];
  ssize_t bytes = read(sock, buffer, sizeof(buffer) - 1);

  close(sock);

  if (bytes > 0) {
    buffer[bytes] = '\0';
    return std::string(buffer);
  }

  return "HATA: Yanıt alınamadı";
}

void printStatus() {
  std::cout << "\n";
  std::cout << "╔══════════════════════════════════════════════════╗\n";
  std::cout << "║          CLARA Security - Durum Raporu           ║\n";
  std::cout << "╠══════════════════════════════════════════════════╣\n";

  std::string response = sendCommand("status");
  std::cout << response << "\n";

  std::cout << "╚══════════════════════════════════════════════════╝\n";
}

void printServices() {
  std::cout << "\n";
  std::cout << "╔══════════════════════════════════════════════════╗\n";
  std::cout << "║               Aktif Servisler                    ║\n";
  std::cout << "╠══════════════════════════════════════════════════╣\n";

  std::string response = sendCommand("services");
  std::cout << response << "\n";

  std::cout << "╚══════════════════════════════════════════════════╝\n";
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printUsage(argv[0]);
    return 1;
  }

  std::string cmd = argv[1];

  if (cmd == "help" || cmd == "-h" || cmd == "--help") {
    printUsage(argv[0]);
    return 0;
  }

  if (cmd == "status") {
    printStatus();
    return 0;
  }

  if (cmd == "services") {
    printServices();
    return 0;
  }

  if (cmd == "start" || cmd == "stop" || cmd == "restart") {
    if (argc < 3) {
      std::cerr << "HATA: Servis adı gerekli\n";
      return 1;
    }

    std::string service_cmd = cmd + " " + argv[2];
    std::cout << sendCommand(service_cmd) << "\n";
    return 0;
  }

  if (cmd == "scan") {
    std::cout << "Tarama başlatılıyor...\n";
    std::cout << sendCommand("scan") << "\n";
    return 0;
  }

  if (cmd == "threats") {
    std::cout << sendCommand("threats") << "\n";
    return 0;
  }

  if (cmd == "trackers") {
    std::cout << sendCommand("trackers") << "\n";
    return 0;
  }

  if (cmd == "lock" || cmd == "unlock") {
    if (argc < 3) {
      std::cerr << "HATA: Paket adı gerekli\n";
      return 1;
    }

    std::string lock_cmd = cmd + " " + argv[2];
    std::cout << sendCommand(lock_cmd) << "\n";
    return 0;
  }

  if (cmd == "hide" || cmd == "unhide") {
    if (argc < 3) {
      std::cerr << "HATA: Paket adı gerekli\n";
      return 1;
    }

    std::string hide_cmd = cmd + " " + argv[2];
    std::cout << sendCommand(hide_cmd) << "\n";
    return 0;
  }

  std::cerr << "Bilinmeyen komut: " << cmd << "\n";
  std::cerr << "Yardım için: " << argv[0] << " help\n";
  return 1;
}
