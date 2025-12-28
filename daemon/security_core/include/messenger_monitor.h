/**
 * CLARA Security - WhatsApp/Telegram Messenger Monitor
 * Mesajlaşma uygulamalarından gelen linkleri izler
 */

#ifndef CLARA_MESSENGER_MONITOR_H
#define CLARA_MESSENGER_MONITOR_H

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace clara {

// Mesaj bilgisi
struct MessengerMessage {
  std::string app;     // whatsapp, telegram, etc.
  std::string sender;  // Gönderen
  std::string content; // Mesaj içeriği
  uint64_t timestamp;
  std::vector<std::string> urls; // Çıkarılan URL'ler
  std::string chat_id;           // Sohbet ID
};

// Desteklenen uygulamalar
enum class MessengerApp {
  WHATSAPP,
  TELEGRAM,
  SIGNAL,
  INSTAGRAM,
  FACEBOOK_MESSENGER
};

/**
 * Messenger Monitor
 * - Notification içeriğini okur (NotificationListenerService)
 * - Veya database'leri okur (root ile)
 * - URL'leri analiz eder
 */
class MessengerMonitor {
public:
  MessengerMonitor();
  ~MessengerMonitor();

  // Lifecycle
  bool initialize();
  void start();
  void stop();
  bool isRunning() const { return running_.load(); }

  // Callback
  using MessageCallback = std::function<void(const MessengerMessage &)>;
  void setMessageCallback(MessageCallback callback) { callback_ = callback; }

  // Uygulama yönetimi
  void enableApp(MessengerApp app);
  void disableApp(MessengerApp app);

  // Manuel tarama
  std::vector<MessengerMessage> scanRecentMessages(MessengerApp app,
                                                   int count = 50);

  // İstatistikler
  int getScannedCount() const { return scanned_count_.load(); }
  int getThreatsFound() const { return threats_found_.load(); }

private:
  void monitorLoop();

  // WhatsApp özellikleri
  std::vector<MessengerMessage> readWhatsAppMessages();
  std::string getWhatsAppDbPath();

  // Telegram özellikleri
  std::vector<MessengerMessage> readTelegramMessages();
  std::string getTelegramDbPath();

  // URL çıkarma ve analiz
  std::vector<std::string> extractUrls(const std::string &text);
  float analyzeUrl(const std::string &url);

  // Notification dinleme (alternatif yöntem)
  void watchNotifications();

  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  MessageCallback callback_;

  // Etkin uygulamalar
  std::unordered_map<MessengerApp, bool> enabled_apps_;

  // Son işlenen mesaj ID'leri
  std::unordered_map<MessengerApp, int64_t> last_message_ids_;

  // İstatistikler
  std::atomic<int> scanned_count_{0};
  std::atomic<int> threats_found_{0};

  // Ayarlar
  int check_interval_ms_ = 2000;
  bool use_notification_method_ = true; // DB yerine notification kullan
};

} // namespace clara

#endif // CLARA_MESSENGER_MONITOR_H
