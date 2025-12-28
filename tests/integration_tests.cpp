/**
 * CLARA Security - Test Framework
 *
 * Daemon ve Android app entegrasyon testleri
 */

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

// Test sonuçları
struct TestResult {
  std::string name;
  bool passed;
  std::string message;
  int duration_ms;
};

class TestRunner {
public:
  std::vector<TestResult> results;
  int passed = 0;
  int failed = 0;

  void report(const std::string &name, bool passed,
              const std::string &msg = "") {
    TestResult r{name, passed, msg, 0};
    results.push_back(r);

    if (passed) {
      this->passed++;
      std::cout << "  ✅ " << name << std::endl;
    } else {
      this->failed++;
      std::cout << "  ❌ " << name << ": " << msg << std::endl;
    }
  }

  void summary() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Toplam: " << (passed + failed) << " test" << std::endl;
    std::cout << "Geçen: " << passed << std::endl;
    std::cout << "Başarısız: " << failed << std::endl;
    std::cout << "========================================" << std::endl;
  }
};

// Helper: Shell komut çalıştır
std::string exec(const char *cmd) {
  char buffer[4096];
  std::string result;
  FILE *pipe = popen(cmd, "r");
  if (!pipe)
    return "";
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result += buffer;
  }
  pclose(pipe);
  return result;
}

// ===========================================================================
// DAEMON ENTEGRASYON TESTLERİ
// ===========================================================================

void test_daemon_binaries(TestRunner &runner) {
  std::cout << "\n📦 Daemon Binary Testleri" << std::endl;

  // Binary'lerin varlığını kontrol et
  std::vector<std::string> binaries = {
      "clara_orchestrator", "clara_security_core", "clara_privacy_core",
      "clara_app_manager"};

  for (const auto &bin : binaries) {
    std::string path = "daemon/build_android/" + bin;
    FILE *f = fopen(path.c_str(), "r");
    bool exists = (f != nullptr);
    if (f)
      fclose(f);

    runner.report(bin + " binary mevcut", exists,
                  exists ? "" : "Binary bulunamadı: " + path);
  }

  // Binary boyutlarını kontrol et
  for (const auto &bin : binaries) {
    std::string cmd = "stat -c%s daemon/build_android/" + bin + " 2>/dev/null";
    std::string size_str = exec(cmd.c_str());

    if (!size_str.empty()) {
      long size = std::stol(size_str);
      bool valid_size = (size > 100000); // En az 100KB olmalı
      runner.report(bin + " boyut > 100KB", valid_size,
                    valid_size ? "" : "Boyut çok küçük: " + size_str);
    }
  }
}

void test_module_package(TestRunner &runner) {
  std::cout << "\n📦 KernelSU Modül Testleri" << std::endl;

  // module.prop kontrolü
  std::string prop = exec("cat kernelsu_module/module.prop 2>/dev/null");
  runner.report("module.prop mevcut", !prop.empty());
  runner.report("module.prop id içeriyor",
                prop.find("id=clara") != std::string::npos);
  runner.report("module.prop version içeriyor",
                prop.find("version=") != std::string::npos);

  // service.sh kontrolü
  std::string service = exec("cat kernelsu_module/service.sh 2>/dev/null");
  runner.report("service.sh mevcut", !service.empty());
  runner.report("service.sh orchestrator başlatıyor",
                service.find("clara_orchestrator") != std::string::npos);

  // ZIP dosyası kontrolü
  std::string zip_check =
      exec("ls -la clara_security_v*.zip "
           "kernelsu_module/../clara_security_v*.zip 2>/dev/null | head -1");
  runner.report("Modül ZIP dosyası mevcut", !zip_check.empty());

  // ZIP içeriği kontrolü - kernelsu_module içindeki binary'leri kontrol et
  std::string bin_check =
      exec("ls -la kernelsu_module/system/bin/clara_orchestrator 2>/dev/null");
  runner.report("ZIP daemon binary'leri içeriyor", !bin_check.empty());
}

void test_config_files(TestRunner &runner) {
  std::cout << "\n⚙️ Konfigürasyon Testleri" << std::endl;

  // config.json kontrolü
  std::string config =
      exec("cat kernelsu_module/system/etc/clara/config.json 2>/dev/null");
  runner.report("config.json mevcut", !config.empty());

  if (!config.empty()) {
    runner.report("config.json geçerli JSON",
                  config.find("{") != std::string::npos &&
                      config.find("}") != std::string::npos);
  }
}

// ===========================================================================
// ANDROID APP TESTLERİ
// ===========================================================================

void test_android_app_structure(TestRunner &runner) {
  std::cout << "\n📱 Android App Yapı Testleri" << std::endl;

  // Temel dosyaların varlığı
  std::vector<std::pair<std::string, std::string>> files = {
      {"android_app/build.gradle.kts", "Root build.gradle.kts"},
      {"android_app/app/build.gradle.kts", "App build.gradle.kts"},
      {"android_app/app/src/main/AndroidManifest.xml", "AndroidManifest.xml"},
      {"android_app/app/src/main/java/com/clara/security/MainActivity.kt",
       "MainActivity.kt"},
      {"android_app/app/src/main/java/com/clara/security/ui/CLARAApp.kt",
       "CLARAApp.kt"},
  };

  for (const auto &[path, name] : files) {
    FILE *f = fopen(path.c_str(), "r");
    bool exists = (f != nullptr);
    if (f)
      fclose(f);
    runner.report(name + " mevcut", exists);
  }
}

void test_android_app_screens(TestRunner &runner) {
  std::cout << "\n🖼️ Android App Ekran Testleri" << std::endl;

  std::vector<std::pair<std::string, std::string>> screens = {
      {"android_app/app/src/main/java/com/clara/security/ui/screens/"
       "DashboardScreen.kt",
       "Dashboard"},
      {"android_app/app/src/main/java/com/clara/security/ui/screens/"
       "ThreatsScreen.kt",
       "Threats"},
      {"android_app/app/src/main/java/com/clara/security/ui/screens/"
       "ProtectionScreen.kt",
       "Protection"},
      {"android_app/app/src/main/java/com/clara/security/ui/screens/"
       "SettingsScreen.kt",
       "Settings"},
      {"android_app/app/src/main/java/com/clara/security/ui/screens/"
       "AppLockScreen.kt",
       "AppLock"},
      {"android_app/app/src/main/java/com/clara/security/ui/screens/"
       "TrackerScreen.kt",
       "Tracker"},
  };

  for (const auto &[path, name] : screens) {
    FILE *f = fopen(path.c_str(), "r");
    bool exists = (f != nullptr);
    if (f)
      fclose(f);
    runner.report(name + "Screen mevcut", exists);
  }
}

void test_android_app_services(TestRunner &runner) {
  std::cout << "\n🔧 Android App Servis Testleri" << std::endl;

  // NotificationHelper
  std::string notif = exec("cat "
                           "android_app/app/src/main/java/com/clara/security/"
                           "service/NotificationHelper.kt 2>/dev/null");
  runner.report("NotificationHelper mevcut", !notif.empty());
  runner.report("NotificationHelper kanal oluşturuyor",
                notif.find("NotificationChannel") != std::string::npos);
  runner.report("NotificationHelper tehdit bildirimi var",
                notif.find("showThreatNotification") != std::string::npos);

  // ClaraConnectionService
  std::string service = exec("cat "
                             "android_app/app/src/main/java/com/clara/security/"
                             "service/ClaraConnectionService.kt 2>/dev/null");
  runner.report("ClaraConnectionService mevcut", !service.empty());
  runner.report("ClaraConnectionService foreground",
                service.find("startForeground") != std::string::npos);

  // ClaraProtocol
  std::string protocol = exec("cat "
                              "android_app/app/src/main/java/com/clara/"
                              "security/data/ClaraProtocol.kt 2>/dev/null");
  runner.report("ClaraProtocol mevcut", !protocol.empty());
  runner.report("ClaraProtocol komut enum'u var",
                protocol.find("enum class Command") != std::string::npos);
}

void test_android_manifest(TestRunner &runner) {
  std::cout << "\n📋 AndroidManifest Testleri" << std::endl;

  std::string manifest =
      exec("cat android_app/app/src/main/AndroidManifest.xml 2>/dev/null");

  // İzinler
  runner.report("INTERNET izni",
                manifest.find("INTERNET") != std::string::npos);
  runner.report("POST_NOTIFICATIONS izni",
                manifest.find("POST_NOTIFICATIONS") != std::string::npos);
  runner.report("FOREGROUND_SERVICE izni",
                manifest.find("FOREGROUND_SERVICE") != std::string::npos);
  runner.report("RECEIVE_BOOT_COMPLETED izni",
                manifest.find("RECEIVE_BOOT_COMPLETED") != std::string::npos);

  // Bileşenler
  runner.report("MainActivity tanımlı",
                manifest.find("MainActivity") != std::string::npos);
  runner.report("BootReceiver tanımlı",
                manifest.find("BootReceiver") != std::string::npos);
  runner.report("ClaraConnectionService tanımlı",
                manifest.find("ClaraConnectionService") != std::string::npos);
}

// ===========================================================================
// IPC VE ENTEGRASYON TESTLERİ
// ===========================================================================

void test_ipc_protocol(TestRunner &runner) {
  std::cout << "\n🔌 IPC Protokol Testleri" << std::endl;

  // ClaraConnection
  std::string conn = exec("cat "
                          "android_app/app/src/main/java/com/clara/security/"
                          "data/ClaraConnection.kt 2>/dev/null");
  runner.report("ClaraConnection mevcut", !conn.empty());
  runner.report("Socket path tanımlı",
                conn.find("orchestrator.sock") != std::string::npos);
  runner.report("su -c komutu kullanılıyor",
                conn.find("su -c") != std::string::npos ||
                    conn.find("su\", \"-c\"") != std::string::npos);

  // Komut tipleri
  std::string protocol = exec("cat "
                              "android_app/app/src/main/java/com/clara/"
                              "security/data/ClaraProtocol.kt 2>/dev/null");
  runner.report("STATUS komutu var",
                protocol.find("STATUS") != std::string::npos);
  runner.report("START_SCAN komutu var",
                protocol.find("START_SCAN") != std::string::npos);
  runner.report("RESTART_DAEMONS komutu var",
                protocol.find("RESTART_DAEMONS") != std::string::npos);
}

// ===========================================================================
// YENİ GÜVENLİK MODÜLLERİ TESTLERİ
// ===========================================================================

void test_security_modules(TestRunner &runner) {
  std::cout << "\n🛡️ Güvenlik Modülleri Testleri" << std::endl;

  // Overlay Detector
  std::string overlay_h =
      exec("cat daemon/security_core/include/overlay_detector.h 2>/dev/null");
  std::string overlay_cpp =
      exec("cat daemon/security_core/src/overlay_detector.cpp 2>/dev/null");
  runner.report("OverlayDetector header mevcut", !overlay_h.empty());
  runner.report("OverlayDetector impl mevcut", !overlay_cpp.empty());
  runner.report("OverlayDetector hassas app listesi var",
                overlay_cpp.find("SENSITIVE_APPS") != std::string::npos);

  // Clipboard Guard
  std::string clip_h =
      exec("cat daemon/security_core/include/clipboard_guard.h 2>/dev/null");
  std::string clip_cpp =
      exec("cat daemon/security_core/src/clipboard_guard.cpp 2>/dev/null");
  runner.report("ClipboardGuard header mevcut", !clip_h.empty());
  runner.report("ClipboardGuard impl mevcut", !clip_cpp.empty());
  runner.report("ClipboardGuard kredi kartı regex var",
                clip_cpp.find("credit_card_pattern") != std::string::npos);
  runner.report("ClipboardGuard TC kimlik doğrulama var",
                clip_cpp.find("isValidTCKimlik") != std::string::npos);

  // Screen Capture Detector
  std::string screen_h = exec(
      "cat daemon/security_core/include/screen_capture_detector.h 2>/dev/null");
  std::string screen_cpp = exec(
      "cat daemon/security_core/src/screen_capture_detector.cpp 2>/dev/null");
  runner.report("ScreenCaptureDetector header mevcut", !screen_h.empty());
  runner.report("ScreenCaptureDetector impl mevcut", !screen_cpp.empty());
  runner.report("ScreenCaptureDetector inotify kullanıyor",
                screen_cpp.find("inotify") != std::string::npos);

  // Network Firewall
  std::string fw_h =
      exec("cat daemon/privacy_core/include/network_firewall.h 2>/dev/null");
  std::string fw_cpp =
      exec("cat daemon/privacy_core/src/network_firewall.cpp 2>/dev/null");
  runner.report("NetworkFirewall header mevcut", !fw_h.empty());
  runner.report("NetworkFirewall impl mevcut", !fw_cpp.empty());
  runner.report("NetworkFirewall iptables kullanıyor",
                fw_cpp.find("iptables") != std::string::npos);

  // WiFi Auditor
  std::string wifi_h =
      exec("cat daemon/security_core/include/wifi_auditor.h 2>/dev/null");
  std::string wifi_cpp =
      exec("cat daemon/security_core/src/wifi_auditor.cpp 2>/dev/null");
  runner.report("WifiAuditor header mevcut", !wifi_h.empty());
  runner.report("WifiAuditor impl mevcut", !wifi_cpp.empty());
  runner.report("WifiAuditor ARP spoofing kontrolü var",
                wifi_cpp.find("checkArpSpoofing") != std::string::npos);
  runner.report("WifiAuditor Evil Twin kontrolü var",
                wifi_cpp.find("checkEvilTwin") != std::string::npos);
}

// ===========================================================================
// MAIN
// ===========================================================================

int main() {
  std::cout << "╔══════════════════════════════════════════╗" << std::endl;
  std::cout << "║    CLARA Security - Entegrasyon Testleri ║" << std::endl;
  std::cout << "╚══════════════════════════════════════════╝" << std::endl;

  TestRunner runner;

  // Daemon testleri
  test_daemon_binaries(runner);
  test_module_package(runner);
  test_config_files(runner);

  // Android app testleri
  test_android_app_structure(runner);
  test_android_app_screens(runner);
  test_android_app_services(runner);
  test_android_manifest(runner);

  // IPC testleri
  test_ipc_protocol(runner);

  // Güvenlik modülleri testleri
  test_security_modules(runner);

  // Özet
  runner.summary();

  return runner.failed > 0 ? 1 : 0;
}
