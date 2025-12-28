/**
 * CLARA Security - AI Engine Implementation
 *
 * Şu an kural tabanlı analiz, ileride TFLite entegrasyonu
 */

#include "../include/ai_engine.h"
#include <algorithm>
#include <regex>
#include <syslog.h>

namespace clara {

AiEngine::AiEngine() { syslog(LOG_INFO, "AI Engine başlatılıyor..."); }

AiEngine::~AiEngine() { syslog(LOG_INFO, "AI Engine kapatılıyor..."); }

bool AiEngine::loadModels(const std::string &model_dir) {
  model_dir_ = model_dir;

  // TODO: TFLite modellerini yükle
  // sms_model_ = loadTFLiteModel(model_dir + "/sms_detector.tflite");
  // malware_model_ = loadTFLiteModel(model_dir + "/malware_classifier.tflite");
  // network_model_ = loadTFLiteModel(model_dir + "/network_anomaly.tflite");

  syslog(LOG_INFO, "AI modelleri yüklendi (kural tabanlı mod aktif)");
  models_loaded_ = true;

  return true;
}

bool AiEngine::updateModel([[maybe_unused]] const std::string &model_name,
                           [[maybe_unused]] const std::string &path) {
  // TODO: Model güncelleme implementasyonu
  syslog(LOG_INFO, "Model güncelleniyor: %s", model_name.c_str());
  return true;
}

// ============================================================================
// SMS Phishing Analizi
// ============================================================================

ThreatInfo AiEngine::analyzeSms(const SmsInfo &sms) {
  ThreatInfo threat;
  threat.source = sms.sender;
  threat.raw_data = sms.body;

  float risk_score = ruleBasedSmsAnalysis(sms);
  threat.confidence = risk_score;

  // Tehdit seviyesi belirleme
  if (risk_score >= 0.85f) {
    threat.level = ThreatLevel::CRITICAL;
    threat.type = "phishing_critical";
    threat.description = "CRITICAL: Phishing SMS tespit edildi";
    threat.recommended_actions = {ActionType::BLOCK, ActionType::NOTIFY};
  } else if (risk_score >= 0.65f) {
    threat.level = ThreatLevel::HIGH;
    threat.type = "phishing_high";
    threat.description = "HIGH: Yüksek olasılıklı phishing";
    threat.recommended_actions = {ActionType::NOTIFY, ActionType::QUARANTINE};
  } else if (risk_score >= 0.45f) {
    threat.level = ThreatLevel::MEDIUM;
    threat.type = "spam_suspicious";
    threat.description = "MEDIUM: Şüpheli mesaj";
    threat.recommended_actions = {ActionType::NOTIFY};
  } else if (risk_score >= 0.25f) {
    threat.level = ThreatLevel::LOW;
    threat.type = "spam_possible";
    threat.description = "LOW: Olası spam";
    threat.recommended_actions = {ActionType::LOG};
  } else {
    threat.level = ThreatLevel::NONE;
    threat.type = "safe";
    threat.description = "Güvenli mesaj";
  }

  return threat;
}

float AiEngine::ruleBasedSmsAnalysis(const SmsInfo &sms) {
  float score = 0.0f;
  std::string body = sms.body;
  std::string body_lower = body;
  std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(),
                 ::tolower);

  // Feature 1: URL sayısı ve türü (0-0.3)
  auto urls = extractUrls(body);
  for (const auto &url : urls) {
    score += 0.05f; // Her URL için küçük puan

    if (isShortUrl(url)) {
      score += 0.15f; // Kısa URL çok şüpheli
    }

    // IP adresi içeren URL
    std::regex ip_regex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
    if (std::regex_search(url, ip_regex)) {
      score += 0.2f;
    }

    // Şüpheli TLD'ler
    std::vector<std::string> bad_tlds = {".ru", ".cn", ".tk",  ".ml", ".ga",
                                         ".cf", ".gq", ".xyz", ".top"};
    for (const auto &tld : bad_tlds) {
      if (url.find(tld) != std::string::npos) {
        score += 0.15f;
        break;
      }
    }
  }

  // Feature 2: Phishing anahtar kelimeleri (0-0.35)
  int keyword_count = 0;
  for (const auto &keyword : phishing_keywords_) {
    if (body_lower.find(keyword) != std::string::npos) {
      keyword_count++;
    }
  }
  score += std::min(0.35f, keyword_count * 0.07f);

  // Feature 3: Banka/finans kelimeleri (0-0.15)
  if (containsBankKeywords(body_lower)) {
    score += 0.15f;
  }

  // Feature 4: Aciliyet ifadeleri (0-0.1)
  std::vector<std::string> urgency = {"acil",        "urgent",      "hemen",
                                      "immediately", "bugün",       "today",
                                      "son şans",    "last chance", "sınırlı",
                                      "limited",     "bekliyor",    "waiting"};
  for (const auto &word : urgency) {
    if (body_lower.find(word) != std::string::npos) {
      score += 0.1f;
      break;
    }
  }

  // Feature 5: Para/ödeme ifadeleri (0-0.1)
  std::vector<std::string> money = {
      "tl",       "lira",       "euro", "dolar", "dollar", "ödeme", "payment",
      "transfer", "kazandınız", "won",  "prize", "hediye", "gift"};
  for (const auto &word : money) {
    if (body_lower.find(word) != std::string::npos) {
      score += 0.1f;
      break;
    }
  }

  // Feature 6: Gönderen analizi (0-0.15)
  // Alfanumerik olmayan, kısa sender'lar daha şüpheli
  if (sms.sender.length() < 5) {
    score += 0.1f;
  }

  // Sadece harflerden oluşan kısa sender (örn: "BANKA")
  bool all_alpha = std::all_of(sms.sender.begin(), sms.sender.end(), ::isalpha);
  if (all_alpha && sms.sender.length() <= 6) {
    score += 0.05f; // Bankalar genelde böyle gönderir ama dikkatli ol
  }

  return std::min(1.0f, score);
}

std::vector<std::string> AiEngine::extractUrls(const std::string &text) {
  std::vector<std::string> urls;
  std::regex url_regex(R"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)",
                       std::regex::icase);

  std::sregex_iterator it(text.begin(), text.end(), url_regex);
  std::sregex_iterator end;

  while (it != end) {
    urls.push_back(it->str());
    ++it;
  }

  return urls;
}

bool AiEngine::isShortUrl(const std::string &url) {
  for (const auto &domain : suspicious_domains_) {
    if (url.find(domain) != std::string::npos) {
      return true;
    }
  }
  return false;
}

bool AiEngine::containsBankKeywords(const std::string &text) {
  std::vector<std::string> bank_keywords = {
      "banka",      "bank",       "hesap",    "account",   "kredi",   "credit",
      "kart",       "card",       "iban",     "swift",     "garanti", "akbank",
      "yapı kredi", "is bankasi", "ziraat",   "halk bank", "vakif",   "deniz",
      "hsbc",       "ing",        "odeabank", "qnb"};

  for (const auto &keyword : bank_keywords) {
    if (text.find(keyword) != std::string::npos) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// Dosya/APK Analizi
// ============================================================================

ThreatInfo AiEngine::analyzeFile(const FileInfo &file) {
  ThreatInfo threat;
  threat.source = file.path;

  float risk_score = ruleBasedFileAnalysis(file);
  threat.confidence = risk_score;

  if (risk_score >= 0.8f) {
    threat.level = ThreatLevel::HIGH;
    threat.type = "malware_suspect";
    threat.description = "Yüksek riskli dosya";
    threat.recommended_actions = {ActionType::QUARANTINE, ActionType::NOTIFY};
  } else if (risk_score >= 0.5f) {
    threat.level = ThreatLevel::MEDIUM;
    threat.type = "potentially_unsafe";
    threat.description = "Potansiyel tehlike";
    threat.recommended_actions = {ActionType::NOTIFY};
  } else if (risk_score >= 0.3f) {
    threat.level = ThreatLevel::LOW;
    threat.type = "low_risk";
    threat.description = "Düşük risk";
    threat.recommended_actions = {ActionType::LOG};
  } else {
    threat.level = ThreatLevel::NONE;
    threat.type = "safe";
    threat.description = "Güvenli dosya";
  }

  return threat;
}

float AiEngine::ruleBasedFileAnalysis(const FileInfo &file) {
  float score = 0.0f;

  if (!file.is_apk) {
    // APK olmayan dosyalar için basit analiz
    return score;
  }

  // 1. Dosya adı analizi
  std::string name_lower = file.name;
  std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                 ::tolower);

  std::vector<std::string> malware_names = {
      "hack",  "crack", "patch",   "keygen",  "loader",
      "cheat", "mod",   "premium", "pro",     "full",
      "bot",   "rat",   "trojan",  "exploit", "payload"};

  for (const auto &name : malware_names) {
    if (name_lower.find(name) != std::string::npos) {
      score += 0.2f;
      break;
    }
  }

  // 2. Boyut analizi
  if (file.size < 10 * 1024) { // 10KB altı
    score += 0.3f;             // Çok küçük APK şüpheli
  }

  // 3. İsim uzunluğu
  if (file.name.length() > 50) {
    score += 0.1f; // Çok uzun isimler şüpheli
  }

  return std::min(1.0f, score);
}

bool AiEngine::isSuspiciousApk(const FileInfo &file) {
  return ruleBasedFileAnalysis(file) >= 0.5f;
}

// ============================================================================
// Ağ Anomali Analizi
// ============================================================================

ThreatInfo AiEngine::analyzeNetworkFlow(const NetworkFlow &flow) {
  ThreatInfo threat;
  threat.source = flow.remote_addr + ":" + std::to_string(flow.remote_port);

  float risk_score = ruleBasedNetworkAnalysis(flow);
  threat.confidence = risk_score;

  if (risk_score >= 0.75f) {
    threat.level = ThreatLevel::HIGH;
    threat.type = "network_anomaly";
    threat.description = "Anormal ağ aktivitesi tespit edildi";
    threat.recommended_actions = {ActionType::ISOLATE_NETWORK,
                                  ActionType::NOTIFY};
  } else if (risk_score >= 0.5f) {
    threat.level = ThreatLevel::MEDIUM;
    threat.type = "suspicious_connection";
    threat.description = "Şüpheli bağlantı";
    threat.recommended_actions = {ActionType::NOTIFY};
  } else if (risk_score >= 0.3f) {
    threat.level = ThreatLevel::LOW;
    threat.type = "unusual_traffic";
    threat.description = "Olağandışı trafik";
    threat.recommended_actions = {ActionType::LOG};
  } else {
    threat.level = ThreatLevel::NONE;
    threat.type = "normal";
    threat.description = "Normal bağlantı";
  }

  return threat;
}

float AiEngine::ruleBasedNetworkAnalysis(const NetworkFlow &flow) {
  float score = 0.0f;

  // 1. Bilinen kötü portlar
  std::vector<uint16_t> suspicious_ports = {
      4444,  // Metasploit default
      5555,  // Android ADB
      6666,  // IRC bot
      6667,  // IRC
      31337, // Back Orifice
      12345, // NetBus
      23,    // Telnet
      445,   // SMB
      1433,  // MSSQL
      3389   // RDP
  };

  for (uint16_t port : suspicious_ports) {
    if (flow.remote_port == port) {
      score += 0.4f;
      break;
    }
  }

  // 2. Çok yüksek veri transferi
  uint64_t total = flow.bytes_sent + flow.bytes_received;
  if (total > 100 * 1024 * 1024) { // 100MB+
    score += 0.2f;
  }

  // 3. Giden > Gelen (data exfiltration?)
  if (flow.bytes_sent > flow.bytes_received * 10 &&
      flow.bytes_sent > 1024 * 1024) {
    score += 0.3f;
  }

  // 4. Bilinmeyen/Şüpheli ülke IP'leri (basit kontrol)
  // TODO: GeoIP entegrasyonu

  return std::min(1.0f, score);
}

// ============================================================================
// Uygulama Davranış Analizi
// ============================================================================

ThreatInfo AiEngine::analyzeAppBehavior(
    const AppInfo &app,
    [[maybe_unused]] const std::vector<std::string> &recent_actions) {
  ThreatInfo threat;
  threat.source = app.package_name;

  float score = 0.0f;

  // 1. Tehlikeli izin kombinasyonları
  bool has_sms = false, has_contacts = false, has_internet = false;
  bool has_accessibility = false, has_device_admin = false;

  for (const auto &perm : app.permissions) {
    if (perm.find("SMS") != std::string::npos)
      has_sms = true;
    if (perm.find("CONTACTS") != std::string::npos)
      has_contacts = true;
    if (perm.find("INTERNET") != std::string::npos)
      has_internet = true;
    if (perm.find("ACCESSIBILITY") != std::string::npos)
      has_accessibility = true;
    if (perm.find("DEVICE_ADMIN") != std::string::npos)
      has_device_admin = true;
  }

  // SMS + İnternet + Rehber = olası veri sızdırma
  if (has_sms && has_internet && has_contacts)
    score += 0.25f;
  else if (has_sms && has_internet)
    score += 0.2f;

  // Accessibility + Device Admin = olası banking trojan
  if (has_accessibility && has_device_admin) {
    score += 0.5f;
    threat.type = "banking_trojan_suspect";
  }

  // 2. Tehlikeli izin sayısı
  int dangerous_count = 0;
  for (const auto &perm : app.permissions) {
    for (const auto &dp : dangerous_permissions_) {
      if (perm == dp)
        dangerous_count++;
    }
  }

  if (dangerous_count >= 5)
    score += 0.3f;
  else if (dangerous_count >= 3)
    score += 0.15f;

  // 3. Sistem uygulaması değilse ve çok fazla izin varsa
  if (!app.is_system && app.permissions.size() > 10) {
    score += 0.1f;
  }

  threat.confidence = std::min(1.0f, score);

  if (score >= 0.6f) {
    threat.level = ThreatLevel::HIGH;
    threat.description = "Yüksek riskli uygulama davranışı";
  } else if (score >= 0.4f) {
    threat.level = ThreatLevel::MEDIUM;
    threat.description = "Şüpheli uygulama davranışı";
  } else if (score >= 0.2f) {
    threat.level = ThreatLevel::LOW;
    threat.description = "Dikkat edilmesi gereken davranış";
  } else {
    threat.level = ThreatLevel::NONE;
    threat.description = "Normal davranış";
  }

  return threat;
}

} // namespace clara
