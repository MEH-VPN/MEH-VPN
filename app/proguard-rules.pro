# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

-keepattributes SourceFile,LineNumberTable
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Keep Go mobile / gomobile / tun2socks JNI bindings and classes
-keep class go.** { *; }
-keep class engine.** { *; }
-keep class tun2socks.** { *; }
-dontwarn go.**
-dontwarn engine.**
-dontwarn tun2socks.**

# Keep V2Ray models and diagnostics
-keep class com.example.model.** { *; }
-keep class com.example.vpn.MehDiag$* { *; }

# OkHttp / Conscrypt warnings
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
