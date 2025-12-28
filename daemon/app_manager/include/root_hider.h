/**
 * CLARA Security - Root Hider
 * Root tespiti yapan uygulamalardan root'u gizler
 */

#ifndef CLARA_ROOT_HIDER_H
#define CLARA_ROOT_HIDER_H

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clara {

// Gizleme durumu
enum class HideStatus {
  NOT_HIDDEN,
  HIDDEN_BASIC,    // Temel gizleme (prop, su binary)
  HIDDEN_ADVANCED, // Gelişmiş (mount namespace, zygisk)
  HIDDEN_STRICT    // Katı mod (denylist + advanced)
};

// Uygulama root tespit bilgisi
struct RootDetectionInfo {
  std::string package_name;
  std::string app_name;
  bool detects_root;   // Root tespit ediyor mu
  bool detects_magisk; // Magisk tespit ediyor mu
  bool uses_safetynet; // SafetyNet/Play Integrity kullanıyor mu
  std::vector<std::string> detection_methods; // Tespit yöntemleri
  HideStatus hide_status;
  bool is_bank_app;
};

/**
 * Root Hider
 * - KernelSU'nun Unmount özelliğini kullanır
 * - Zygisk modülleri ile entegre olur
 * - Prop'ları gizler
 * - Su binary'sini gizler
 */
class RootHider {
public:
  RootHider();
  ~RootHider();

  // Lifecycle
  bool initialize();
  void start();
  void stop();
  bool isRunning() const { return running_.load(); }

  // Uygulama bazlı gizleme
  void hideFromApp(const std::string &package_name);
  void unhideFromApp(const std::string &package_name);
  bool isHiddenFrom(const std::string &package_name);
  HideStatus getHideStatus(const std::string &package_name);

  // Gizleme seviyesi
  void setHideLevel(const std::string &package_name, HideStatus level);

  // Otomatik tespit
  std::vector<RootDetectionInfo> scanForRootDetectors();
  bool doesAppDetectRoot(const std::string &package_name);

  // Banka uygulamaları (otomatik tespit ve gizleme)
  std::vector<std::string> detectBankApps();
  void autoHideBankApps();

  // KernelSU entegrasyonu
  bool isKernelSuAvailable();
  bool addToKsuDenylist(const std::string &package_name);
  bool removeFromKsuDenylist(const std::string &package_name);
  std::vector<std::string> getKsuDenylist();

  // Prop gizleme
  void hideRootProps();
  void restoreRootProps();

  // Su binary gizleme
  void hideSuBinary();
  void restoreSuBinary();

  // Gizlenen uygulamalar listesi
  std::vector<std::string> getHiddenPackages();
  std::vector<RootDetectionInfo> getAllAppsInfo();

  // Test
  bool testHiding(const std::string &
                      package_name); // Gizlemenin çalışıp çalışmadığını test et

private:
  void monitorLoop();

  // Root tespit yöntemleri analizi
  std::vector<std::string>
  analyzeDetectionMethods(const std::string &package_name);

  // KernelSU komutları
  std::string runKsuCommand(const std::string &cmd);

  // Prop manipülasyonu
  std::string getOriginalProp(const std::string &prop_name);
  void setProp(const std::string &prop_name, const std::string &value);
  void resetProp(const std::string &prop_name);

  // Mount namespace
  bool setupMountNamespace(const std::string &package_name);

  // Package analizi
  bool isAppInstalled(const std::string &package_name);
  std::string getAppPath(const std::string &package_name);

  std::atomic<bool> running_{false};
  std::thread monitor_thread_;

  // Gizlenen uygulamalar
  std::unordered_set<std::string> hidden_packages_;
  std::unordered_map<std::string, HideStatus> hide_levels_;
  std::unordered_map<std::string, RootDetectionInfo> app_info_;

  // Bilinen banka uygulamaları (Türkiye)
  std::unordered_set<std::string> known_bank_apps_ = {
      "com.tmobtech.halkbank",
      "com.akbank.android.apps.akbank_direkt",
      "com.garanti.cepsubesi",
      "com.ykb.android",
      "com.ziraat.ziraatmobil",
      "com.vakifbank.mobile",
      "com.ingbanktr.ingmobil",
      "tr.com.sekerbilisim.mbank",
      "com.teb",
      "com.denizbank.mobildeniz",
      "com.finansbank.mobile.cepsube",
      "com.pttbank.pttbank",
      "tr.gov.turkiye.edevlet.kapisi",
      "com.magiclick.odeabank"};

  // Bilinen root tespit yapan uygulamalar
  std::unordered_set<std::string> known_detectors_ = {
      "com.scottyab.rootbeer.sample", "com.geny.rootchecker"};

  // Gizlenecek prop'lar
  std::vector<std::pair<std::string, std::string>> root_props_ = {
      {"ro.build.tags", "release-keys"},
      {"ro.debuggable", "0"},
      {"ro.secure", "1"},
      {"ro.build.type", "user"},
      {"ro.build.selinux", "1"}};

  std::string config_path_ = "/data/clara/roothider.json";
};

} // namespace clara

#endif // CLARA_ROOT_HIDER_H
