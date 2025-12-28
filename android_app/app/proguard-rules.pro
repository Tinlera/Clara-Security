# Add project specific ProGuard rules here.

# Keep data classes
-keepclassmembers class com.clara.security.model.** {
    *;
}

# Keep Compose
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# Keep Coroutines
-keepclassmembers class kotlinx.coroutines.** {
    volatile *;
}
-dontwarn kotlinx.coroutines.**

# Keep Gson (if used)
-keepattributes Signature
-keepattributes *Annotation*
