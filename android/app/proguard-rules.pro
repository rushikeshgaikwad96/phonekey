# PhoneKey Android App ProGuard / R8 Rules

# Preserve Jetpack Compose rules
-keepclassmembers class * extends androidx.compose.ui.node.LayoutNode { *; }

# Preserve AndroidX BiometricPrompt and Cryptographic Classes
-keep class androidx.biometric.** { *; }
-keep class androidx.security.crypto.** { *; }
-keep class com.phonekey.crypto.** { *; }
-keep class com.phonekey.engine.** { *; }
-keep class com.phonekey.pairing.** { *; }
-keep class com.phonekey.transport.** { *; }
