/**
 * CLARA Security - SMS Monitor Module
 * AI destekli SMS phishing/scam tespiti
 */

#ifndef CLARA_SMS_MONITOR_H
#define CLARA_SMS_MONITOR_H

#include "clara_daemon.h"
#include <regex>

namespace clara {

/**
 * SMS izleme modülü
 * ContentObserver yerine root yetkileriyle doğrudan SMS DB okuma
 */
class SmsMonitor : public IModule {
public:
  SmsMonitor();
  ~SmsMonitor() override;

  // IModule implementasyonu
  const std::string &getName() const override { return name_; }
  bool initialize() override;
  void start() override;
  void stop() override;
  bool isRunning() const override { return running_.load(); }
  void setEventCallback(EventCallback callback) override {
    callback_ = callback;
  }

  // SMS analiz
  ThreatInfo analyzeSms(const SmsInfo &sms);

  // İstatistikler
  int getBlockedCount() const { return blocked_count_.load(); }
  int getScannedCount() const { return scanned_count_.load(); }

private:
  void monitorLoop();
  std::vector<SmsInfo> readNewSms();
  bool isPhishingUrl(const std::string &url);
  bool containsSuspiciousKeywords(const std::string &text);
  float calculateRiskScore(const SmsInfo &sms);

  std::string name_ = "sms_monitor";
  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
  EventCallback callback_;

  // Son işlenen SMS ID'si
  int64_t last_sms_id_ = 0;

  // İstatistikler
  std::atomic<int> blocked_count_{0};
  std::atomic<int> scanned_count_{0};

  // Phishing pattern'leri
  std::vector<std::regex> phishing_patterns_;
  std::vector<std::string> suspicious_keywords_;

  // Ayarlar
  int check_interval_ms_ = 1000;
  [[maybe_unused]] bool ai_enabled_ = true;
  bool auto_block_ = false;
};

} // namespace clara

#endif // CLARA_SMS_MONITOR_H
