/**
 * CLARA Security - Clipboard Guard Implementation
 */

#include "../include/clipboard_guard.h"
#include <algorithm>
#include <cstdio>
#include <functional>
#include <sstream>
#include <syslog.h>
#include <thread>
#include <unistd.h>

namespace clara {

// BIP39 seed phrase kelimeleri (ilk 20 örnek)
static const std::vector<std::string> BIP39_WORDS = {
    "abandon", "ability",  "able",     "about",  "above",
    "absent",  "absorb",   "abstract", "absurd", "abuse",
    "access",  "accident", "account",  "accuse", "achieve",
    "acid",    "acoustic", "acquire",  "across", "act",
    "action",  "actor",    "actress",  "actual"
    // ... gerçek implementasyonda 2048 kelime
};

ClipboardGuard::ClipboardGuard() : running_(false), auto_clear_seconds_(0) {

  syslog(LOG_INFO, "ClipboardGuard oluşturuluyor...");

  // Regex pattern'leri derle
  // Kredi kartı (16 haneli, boşluk veya tire ile ayrılmış olabilir)
  credit_card_pattern_ = std::regex(R"(\b(?:\d{4}[\s-]?){3}\d{4}\b)");

  // Telefon numarası (Türkiye formatı)
  phone_pattern_ = std::regex(
      R"(\b(?:\+90|0)?[\s.-]?5\d{2}[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}\b)");

  // E-posta
  email_pattern_ =
      std::regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)");

  // IBAN (TR formatı)
  iban_pattern_ = std::regex(
      R"(\bTR\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{2}\b)",
      std::regex::icase);

  // TC Kimlik (11 haneli)
  tc_pattern_ = std::regex(R"(\b[1-9]\d{10}\b)");

  // Bitcoin adresi
  crypto_btc_pattern_ =
      std::regex(R"(\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b)");

  // Ethereum adresi
  crypto_eth_pattern_ = std::regex(R"(\b0x[a-fA-F0-9]{40}\b)");

  // API Key (generic - 32+ karakter alphanumeric)
  api_key_pattern_ = std::regex(
      R"(\b(?:sk|pk|api|key|token)[-_]?[A-Za-z0-9]{32,}\b)", std::regex::icase);

  // OTP (4-8 haneli sayı)
  otp_pattern_ = std::regex(R"(\b\d{4,8}\b)");

  // Seed phrase (12-24 kelime)
  seed_phrase_pattern_ = std::regex(R"(\b([a-z]+\s+){11,23}[a-z]+\b)");

  // Varsayılan izlenen tipler
  monitored_types_ = {
      SensitiveDataType::CREDIT_CARD, SensitiveDataType::CRYPTO_WALLET,
      SensitiveDataType::API_KEY,     SensitiveDataType::SEED_PHRASE,
      SensitiveDataType::PRIVATE_KEY, SensitiveDataType::OTP_CODE,
      SensitiveDataType::TC_KIMLIK,   SensitiveDataType::IBAN};
}

ClipboardGuard::~ClipboardGuard() { stop(); }

bool ClipboardGuard::initialize() {
  syslog(LOG_INFO, "ClipboardGuard başlatılıyor...");
  return true;
}

void ClipboardGuard::stop() {
  running_ = false;
  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }
  syslog(LOG_INFO, "ClipboardGuard durduruldu");
}

std::string ClipboardGuard::getClipboardContent() {
  // Android'de clipboard içeriğini oku
  std::string result;

  // Yöntem 1: service call
  FILE *pipe =
      popen("service call clipboard 2 s16 com.clara.security 2>/dev/null", "r");
  if (pipe) {
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
      result += buffer;
    }
    pclose(pipe);
  }

  // Eğer boşsa, alternatif yöntem
  if (result.empty() || result.find("Result:") == std::string::npos) {
    pipe =
        popen("dumpsys clipboard 2>/dev/null | grep -A5 'mPrimaryClip'", "r");
    if (pipe) {
      char buffer[4096];
      while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
      }
      pclose(pipe);
    }
  }

  return result;
}

std::string ClipboardGuard::getClipboardSource() {
  std::string result;
  FILE *pipe = popen(
      "dumpsys clipboard 2>/dev/null | grep 'mPrimaryClipPackage' | head -1",
      "r");
  if (pipe) {
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), pipe)) {
      result = buffer;
      // Package adını çıkar
      size_t pos = result.find("=");
      if (pos != std::string::npos) {
        result = result.substr(pos + 1);
        result.erase(result.find_last_not_of(" \t\n\r") + 1);
      }
    }
    pclose(pipe);
  }
  return result;
}

SensitiveDataType ClipboardGuard::analyzeContent(const std::string &content) {
  if (content.empty()) {
    return SensitiveDataType::NONE;
  }

  // Öncelik sırasına göre kontrol et (en hassas önce)

  // Seed phrase (12-24 kelime)
  if (std::regex_search(content, seed_phrase_pattern_)) {
    // BIP39 kelimelerini içeriyor mu?
    int bip39_count = 0;
    std::istringstream iss(content);
    std::string word;
    while (iss >> word) {
      std::transform(word.begin(), word.end(), word.begin(), ::tolower);
      if (std::find(BIP39_WORDS.begin(), BIP39_WORDS.end(), word) !=
          BIP39_WORDS.end()) {
        bip39_count++;
      }
    }
    if (bip39_count >= 10) {
      syslog(LOG_ALERT, "SEED PHRASE tespit edildi!");
      return SensitiveDataType::SEED_PHRASE;
    }
  }

  // Private key (hex format)
  if (content.length() >= 64 && content.length() <= 128) {
    bool all_hex = true;
    for (char c : content) {
      if (!isxdigit(c) && c != ' ' && c != '-') {
        all_hex = false;
        break;
      }
    }
    if (all_hex) {
      return SensitiveDataType::PRIVATE_KEY;
    }
  }

  // Kripto cüzdan
  if (std::regex_search(content, crypto_btc_pattern_) ||
      std::regex_search(content, crypto_eth_pattern_)) {
    return SensitiveDataType::CRYPTO_WALLET;
  }

  // API Key
  if (std::regex_search(content, api_key_pattern_)) {
    return SensitiveDataType::API_KEY;
  }

  // Kredi kartı
  if (std::regex_search(content, credit_card_pattern_)) {
    // Sadece rakamları al
    std::string digits;
    for (char c : content) {
      if (isdigit(c))
        digits += c;
    }
    if (digits.length() >= 13 && digits.length() <= 19 &&
        isValidCreditCard(digits)) {
      return SensitiveDataType::CREDIT_CARD;
    }
  }

  // IBAN
  if (std::regex_search(content, iban_pattern_)) {
    return SensitiveDataType::IBAN;
  }

  // TC Kimlik
  if (std::regex_search(content, tc_pattern_)) {
    std::smatch match;
    if (std::regex_search(content, match, tc_pattern_)) {
      if (isValidTCKimlik(match[0].str())) {
        return SensitiveDataType::TC_KIMLIK;
      }
    }
  }

  // OTP (son kontrol - çok genel)
  if (content.length() >= 4 && content.length() <= 8) {
    bool all_digits = true;
    for (char c : content) {
      if (!isdigit(c)) {
        all_digits = false;
        break;
      }
    }
    if (all_digits) {
      return SensitiveDataType::OTP_CODE;
    }
  }

  return SensitiveDataType::NONE;
}

bool ClipboardGuard::isValidCreditCard(const std::string &number) {
  // Luhn algoritması
  int sum = 0;
  bool alternate = false;

  for (int i = number.length() - 1; i >= 0; i--) {
    int digit = number[i] - '0';

    if (alternate) {
      digit *= 2;
      if (digit > 9)
        digit -= 9;
    }

    sum += digit;
    alternate = !alternate;
  }

  return (sum % 10 == 0);
}

bool ClipboardGuard::isValidTCKimlik(const std::string &number) {
  if (number.length() != 11 || number[0] == '0') {
    return false;
  }

  // TC Kimlik doğrulama algoritması
  int digits[11];
  for (int i = 0; i < 11; i++) {
    digits[i] = number[i] - '0';
  }

  // 10. hane kontrolü
  int sum_odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
  int sum_even = digits[1] + digits[3] + digits[5] + digits[7];
  int check10 = ((sum_odd * 7) - sum_even) % 10;
  if (check10 < 0)
    check10 += 10;

  if (digits[9] != check10)
    return false;

  // 11. hane kontrolü
  int sum_all = 0;
  for (int i = 0; i < 10; i++) {
    sum_all += digits[i];
  }

  return (digits[10] == sum_all % 10);
}

std::string ClipboardGuard::maskContent(const std::string &content,
                                        SensitiveDataType type) {
  if (content.length() <= 4) {
    return "****";
  }

  switch (type) {
  case SensitiveDataType::CREDIT_CARD:
    return content.substr(0, 4) + " **** **** " +
           content.substr(content.length() - 4);
  case SensitiveDataType::CRYPTO_WALLET:
    return content.substr(0, 6) + "..." + content.substr(content.length() - 4);
  case SensitiveDataType::TC_KIMLIK:
    return "***" + content.substr(content.length() - 4);
  case SensitiveDataType::SEED_PHRASE:
    return "[SEED PHRASE - GİZLİ]";
  case SensitiveDataType::PRIVATE_KEY:
    return "[PRIVATE KEY - GİZLİ]";
  default:
    return content.substr(0, 3) + "***" + content.substr(content.length() - 2);
  }
}

std::string ClipboardGuard::hashContent(const std::string &content) {
  // Basit hash (gerçek implementasyonda SHA256 kullan)
  std::hash<std::string> hasher;
  return std::to_string(hasher(content));
}

int ClipboardGuard::calculateRiskScore(
    SensitiveDataType type, [[maybe_unused]] const std::string &content) {
  switch (type) {
  case SensitiveDataType::SEED_PHRASE:
  case SensitiveDataType::PRIVATE_KEY:
    return 100; // Kritik
  case SensitiveDataType::CRYPTO_WALLET:
  case SensitiveDataType::API_KEY:
    return 85;
  case SensitiveDataType::CREDIT_CARD:
    return 80;
  case SensitiveDataType::TC_KIMLIK:
  case SensitiveDataType::IBAN:
    return 70;
  case SensitiveDataType::OTP_CODE:
    return 50;
  case SensitiveDataType::PASSWORD:
    return 60;
  default:
    return 0;
  }
}

SensitiveDataType ClipboardGuard::checkCurrentClipboard() {
  stats_.total_checks++;
  stats_.last_check_time =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  std::string content = getClipboardContent();
  std::string hash = hashContent(content);

  // Değişmediyse skip
  if (hash == last_clipboard_hash_) {
    return SensitiveDataType::NONE;
  }

  last_clipboard_hash_ = hash;

  SensitiveDataType type = analyzeContent(content);

  if (type != SensitiveDataType::NONE) {
    // İzlenen tiplerden mi?
    if (std::find(monitored_types_.begin(), monitored_types_.end(), type) !=
        monitored_types_.end()) {
      stats_.sensitive_detections++;

      ClipboardEvent event;
      event.timestamp = stats_.last_check_time;
      event.content = maskContent(content, type);
      event.source_package = getClipboardSource();
      event.data_type = type;
      event.was_auto_cleared = false;
      event.risk_score = calculateRiskScore(type, content);

      // Geçmişe ekle
      event_history_.push_back(event);
      if (event_history_.size() > 100) {
        event_history_.erase(event_history_.begin());
      }

      // Callback
      if (callback_) {
        callback_(event);
      }

      syslog(LOG_WARNING, "Hassas veri panoya kopyalandı: %s (risk: %d)",
             maskContent(content, type).c_str(), event.risk_score);

      // Otomatik temizleme
      if (auto_clear_seconds_ > 0) {
        std::thread([this]() {
          std::this_thread::sleep_for(
              std::chrono::seconds(auto_clear_seconds_));
          clearClipboard();
          stats_.auto_clears++;
        }).detach();
      }
    }
  }

  return type;
}

void ClipboardGuard::clearClipboard() {
  // Panoyu temizle
  FILE *pipe = popen("service call clipboard 3 i32 1 i32 -1 2>/dev/null", "r");
  if (pipe) {
    pclose(pipe);
  }

  // Alternatif yöntem
  popen("am broadcast -a clipper.set -e text '' 2>/dev/null", "r");

  last_clipboard_hash_ = "";
  syslog(LOG_INFO, "Pano temizlendi");
}

void ClipboardGuard::setAutoClearTimeout(int seconds) {
  auto_clear_seconds_ = seconds;
  syslog(LOG_INFO, "Otomatik temizleme: %d saniye", seconds);
}

void ClipboardGuard::setCallback(SensitiveDataCallback callback) {
  callback_ = callback;
}

std::vector<ClipboardEvent> ClipboardGuard::getRecentEvents(int count) {
  int start = std::max(0, (int)event_history_.size() - count);
  return std::vector<ClipboardEvent>(event_history_.begin() + start,
                                     event_history_.end());
}

ClipboardGuard::Stats ClipboardGuard::getStats() const { return stats_; }

void ClipboardGuard::setMonitoredTypes(
    const std::vector<SensitiveDataType> &types) {
  monitored_types_ = types;
}

void ClipboardGuard::startMonitoring(int interval_ms) {
  if (running_)
    return;

  running_ = true;
  monitor_thread_ =
      std::thread(&ClipboardGuard::monitorLoop, this, interval_ms);
  syslog(LOG_INFO, "Clipboard izleme başlatıldı (interval: %dms)", interval_ms);
}

void ClipboardGuard::monitorLoop(int interval_ms) {
  while (running_) {
    checkCurrentClipboard();
    std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
  }
}

} // namespace clara
