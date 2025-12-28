/**
 * CLARA Security - Clipboard Guard
 *
 * Panoya kopyalanan hassas verileri tespit eder:
 * - Kredi kartı numaraları
 * - Şifreler
 * - API anahtarları
 * - Kripto cüzdan adresleri
 */

#ifndef CLARA_CLIPBOARD_GUARD_H
#define CLARA_CLIPBOARD_GUARD_H

#include <chrono>
#include <functional>
#include <regex>
#include <string>
#include <thread>
#include <vector>

namespace clara {

/**
 * Hassas veri tipi
 */
enum class SensitiveDataType {
  NONE,
  CREDIT_CARD,   // Kredi kartı numarası
  PHONE_NUMBER,  // Telefon numarası
  EMAIL,         // E-posta adresi
  PASSWORD,      // Olası şifre
  API_KEY,       // API anahtarı
  CRYPTO_WALLET, // Kripto cüzdan adresi
  IBAN,          // IBAN numarası
  TC_KIMLIK,     // TC Kimlik No
  PRIVATE_KEY,   // Özel anahtar
  SEED_PHRASE,   // Kripto seed phrase
  OTP_CODE,      // Tek kullanımlık şifre
  OTHER
};

/**
 * Clipboard olayı
 */
struct ClipboardEvent {
  int64_t timestamp;
  std::string content;        // Pano içeriği (maskelenmiş)
  std::string source_package; // Hangi uygulama kopyaladı
  SensitiveDataType data_type;
  bool was_auto_cleared; // Otomatik temizlendi mi
  int risk_score;        // 0-100 risk puanı
};

/**
 * Clipboard Guard sınıfı
 */
class ClipboardGuard {
public:
  ClipboardGuard();
  ~ClipboardGuard();

  /**
   * Guard'ı başlat
   */
  bool initialize();

  /**
   * Guard'ı durdur
   */
  void stop();

  /**
   * Sürekli izleme başlat
   * @param interval_ms Kontrol aralığı
   */
  void startMonitoring(int interval_ms = 500);

  /**
   * Mevcut pano içeriğini kontrol et
   * @return Tespit edilen veri tipi
   */
  SensitiveDataType checkCurrentClipboard();

  /**
   * Panoyu temizle
   */
  void clearClipboard();

  /**
   * Belirli süre sonra otomatik temizleme ayarla
   * @param seconds Saniye (0 = devre dışı)
   */
  void setAutoClearTimeout(int seconds);

  /**
   * Hassas veri callback'i
   */
  using SensitiveDataCallback = std::function<void(const ClipboardEvent &)>;
  void setCallback(SensitiveDataCallback callback);

  /**
   * Son olayları al
   */
  std::vector<ClipboardEvent> getRecentEvents(int count = 20);

  /**
   * İstatistikler
   */
  struct Stats {
    int total_checks;
    int sensitive_detections;
    int auto_clears;
    int64_t last_check_time;
  };
  Stats getStats() const;

  /**
   * Belirli veri tiplerini izlemeyi aç/kapa
   */
  void setMonitoredTypes(const std::vector<SensitiveDataType> &types);

private:
  bool running_;
  std::thread monitor_thread_;
  SensitiveDataCallback callback_;

  int auto_clear_seconds_;
  std::string last_clipboard_hash_;
  std::vector<ClipboardEvent> event_history_;
  Stats stats_;

  std::vector<SensitiveDataType> monitored_types_;

  // Regex patterns
  std::regex credit_card_pattern_;
  std::regex phone_pattern_;
  std::regex email_pattern_;
  std::regex iban_pattern_;
  std::regex tc_pattern_;
  std::regex crypto_btc_pattern_;
  std::regex crypto_eth_pattern_;
  std::regex api_key_pattern_;
  std::regex otp_pattern_;
  std::regex seed_phrase_pattern_;

  // Yardımcı fonksiyonlar
  std::string getClipboardContent();
  std::string getClipboardSource();
  SensitiveDataType analyzeContent(const std::string &content);
  std::string maskContent(const std::string &content, SensitiveDataType type);
  std::string hashContent(const std::string &content);
  void monitorLoop(int interval_ms);
  bool isValidCreditCard(const std::string &number);
  bool isValidTCKimlik(const std::string &number);
  int calculateRiskScore(SensitiveDataType type, const std::string &content);
};

} // namespace clara

#endif // CLARA_CLIPBOARD_GUARD_H
