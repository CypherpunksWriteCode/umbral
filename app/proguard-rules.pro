# --- tor-android (BSD-3): libtor.so accesses TorService fields/methods by name
# through JNI (GetFieldID "torConfiguration" "J" etc.). Its AAR ships no
# consumer rules — without these keeps R8 renames the members and the daemon
# crashes with NoSuchFieldError.
-keep class org.torproject.jni.** { *; }

# --- jtorctl: control connection used by TorService and our controller
-keep class net.freehaven.tor.control.** { *; }

# --- IPtProxy (gomobile): go.Seq uses reflection over generated proxies
-keep class go.** { *; }
-keep class IPtProxy.** { *; }

# --- hev-socks5-tunnel: JNI RegisterNatives targets hev.htproxy.TProxyService
-keep class hev.htproxy.** { *; }

# --- kotlinx-serialization: keep generated serializers of our models
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class org.umbral.core.model.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class org.umbral.core.model.**$$serializer { *; }

# --- keep line numbers for readable local crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
