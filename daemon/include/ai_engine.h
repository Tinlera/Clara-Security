/**
 * CLARA Security - AI Inference Engine
 * TensorFlow Lite tabanlı AI motorunu
 */

#ifndef CLARA_AI_ENGINE_H
#define CLARA_AI_ENGINE_H

#include "clara_daemon.h"

// TensorFlow Lite (ileride eklenecek)
// #include "tensorflow/lite/interpreter.h"
// #include "tensorflow/lite/model.h"

namespace clara {

/**
 * AI Inference Engine implementasyonu
 * Şu an basit kural tabanlı, ileride TFLite eklenecek
 */
class AiEngine : public IAiEngine {
public:
  AiEngine();
  ~AiEngine() override;

  // SMS phishing analizi
  ThreatInfo analyzeSms(const SmsInfo &sms) override;

  // Dosya/APK malware analizi
  ThreatInfo analyzeFile(const FileInfo &file) override;

  // Ağ anomali analizi
  ThreatInfo analyzeNetworkFlow(const NetworkFlow &flow) override;

  // Uygulama davranış analizi
  ThreatInfo
  analyzeAppBehavior(const AppInfo &app,
                     const std::vector<std::string> &recent_actions) override;

  // Model yönetimi
  bool loadModels(const std::string &model_dir) override;
  bool updateModel(const std::string &model_name,
                   const std::string &path) override;

  // Konfigürasyon
  void setNumThreads(int threads) { num_threads_ = threads; }
  void setUseNnapi(bool use) { use_nnapi_ = use; }

private:
  // Rule-based analiz (TFLite olmadan)
  float ruleBasedSmsAnalysis(const SmsInfo &sms);
  float ruleBasedFileAnalysis(const FileInfo &file);
  float ruleBasedNetworkAnalysis(const NetworkFlow &flow);

  // Yardımcı fonksiyonlar
  std::vector<std::string> extractUrls(const std::string &text);
  bool isShortUrl(const std::string &url);
  bool containsBankKeywords(const std::string &text);
  bool isSuspiciousApk(const FileInfo &file);

  // TFLite modelleri (ileride)
  // std::unique_ptr<tflite::Interpreter> sms_model_;
  // std::unique_ptr<tflite::Interpreter> malware_model_;
  // std::unique_ptr<tflite::Interpreter> network_model_;

  bool models_loaded_ = false;
  int num_threads_ = 2;
  bool use_nnapi_ = true;
  std::string model_dir_;

  // Phishing patterns
  std::vector<std::string> phishing_keywords_ = {
      "hesabınız", "account", "şifre", "password", "urgent",   "acil",
      "kredi",     "credit",  "banka", "bank",     "doğrula",  "verify",
      "güncelle",  "update",  "ödeme", "payment",  "fatura",   "invoice",
      "kart",      "card",    "limit", "aşıldı",   "exceeded", "bloke",
      "blocked",   "tıkla",   "click", "link",     "giriş",    "login",
      "kayıt",     "register"};

  std::vector<std::string> suspicious_domains_ = {
      "bit.ly",  "tinyurl", "t.co",    "goo.gl",  "is.gd",
      "buff.ly", "ow.ly",   "tiny.cc", "lnkd.in", "rebrand.ly"};

  // Tehlikeli izinler
  std::vector<std::string> dangerous_permissions_ = {
      "android.permission.SEND_SMS",
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.READ_CONTACTS",
      "android.permission.WRITE_CONTACTS",
      "android.permission.RECORD_AUDIO",
      "android.permission.CAMERA",
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.READ_CALL_LOG",
      "android.permission.WRITE_CALL_LOG",
      "android.permission.PROCESS_OUTGOING_CALLS",
      "android.permission.READ_EXTERNAL_STORAGE",
      "android.permission.WRITE_EXTERNAL_STORAGE",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.REQUEST_INSTALL_PACKAGES",
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "android.permission.BIND_DEVICE_ADMIN"};
};

} // namespace clara

#endif // CLARA_AI_ENGINE_H
