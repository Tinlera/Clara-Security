# CLARA Security Android App - Geliştirici Rehberi

Bu proje Android Studio ile geliştirilmek üzere hazırlanmıştır.

## 🛠️ Kurulum ve Android Studio'da Açma

1.  **Android Studio'yu Başlatın.**
    *   "Welcome to Android Studio" ekranında **Open** (veya **Open an existing Android Studio project**) seçeneğine tıklayın.
2.  **Proje Dizinini Seçin:**
    *   Dosya gezgininde `Clara-Security/android_app` klasörünü bulun ve seçin.
    *   **Önemli:** Projenin kök klasörünü değil, `android_app` klasörünü açtığınızdan emin olun (bu klasörde `build.gradle.kts` ve `settings.gradle.kts` dosyaları bulunur).
3.  **Projenin Yüklenmesini Bekleyin (Gradle Sync):**
    *   Android Studio projeyi açtığında otomatik olarak Gradle Sync işlemini başlatacaktır.
    *   Bu işlem gerekli kütüphanelerin indirilmesini sağlar. İnternet hızınıza bağlı olarak birkaç dakika sürebilir.
    *   *Sağ alt köşedeki ilerleme çubuğunu takip edebilirsiniz.*

## ⚙️ Olası Sorunlar ve Çözümleri

### 1. SDK Yolu Hatası (`sdk.dir` missing)
Eğer "SDK location not found" hatası alırsanız:
*   Android Studio genellikle `local.properties` dosyasını otomatik oluşturur veya günceller.
*   Eğer oluşturmazsa, `android_app` klasöründeki `local.properties` doyasını açın ve `sdk.dir` satırını kendi Android SDK yolunuzla değiştirin.
    *   **Windows:** `sdk.dir=C\:\\Users\\KULLANICI_ADI\\AppData\\Local\\Android\\Sdk`
    *   **macOS:** `sdk.dir=/Users/KULLANICI_ADI/Library/Android/sdk`
    *   **Linux:** `sdk.dir=/home/KULLANICI_ADI/Android/Sdk`

### 2. JDK/Java Sürümü Hatası
*   Bu proje **Java 17** veya **Java 21** gerektirir.
*   Android Studio'da: `Settings/Preferences` > `Build, Execution, Deployment` > `Build Tools` > `Gradle` menüsüne gidin.
*   **Gradle JDK** kısmında en az sürüm 17'nin seçili olduğundan emin olun.

## 📱 Uygulamayı Çalıştırma (Run)

1.  Cihazınızı USB ile bağlayın ve **USB Debugging** (Geliştirici Seçenekleri'nden) açık olduğundan emin olun.
2.  Android Studio üst barında cihazınızı seçin.
3.  yeşil **Run** (▶️) butonuna tıklayın.

## 📦 APK Oluşturma (Build)

1.  Menüden **Build** > **Build Bundle(s) / APK(s)** > **Build APK(s)** seçeneğine tıklayın.
2.  Derleme tamamlandığında sağ altta bir bildirim belirecektir. **locate** linkine tıklayarak APK dosyasını bulabilirsiniz.
    *   APK yolu genellikle: `android_app/app/build/outputs/apk/debug/app-debug.apk`

---
**Clara Security Team**
