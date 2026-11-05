# NixOS development toolchain for building the Android app on hosts without
# nix-ld (all binaries come pre-patched from nixpkgs).
#
# Note: androidenv's composite `androidsdk` currently pulls cmdline-tools from
# a dead URL (Google removes old artifacts). We therefore compose the SDK from
# individual components, which is all Gradle needs.
#
# Usage: nix-shell shell.nix
{
  pkgs ? import <unstable> { config = { allowUnfree = true; }; },
}:
let
  android = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ "37.0" ];
    buildToolsVersions = [ "36.1.0" ];
  };
  # platforms / build-tools are lists keyed by our selections above
  platforms35 = builtins.head android.platforms;
  buildTools35 = builtins.head android.build-tools;

  sdk = pkgs.buildEnv {
    name = "umbral-android-sdk";
    paths = [ platforms35 buildTools35 android.platform-tools ];
    pathsToLink = [ "/libexec/android-sdk" ];
    postBuild = ''
      mkdir -p $out/licenses
      printf 'd56f5187479451eabf01fb78af6dfcb131a6481e\n24333f8a63b6825ea9c5514f83c2829b004d1fee\n' > $out/licenses/android-sdk-license
      printf 'd975f751698a77b662f1254ddbeed3901e976f5a\n84831b9400004f1b6dc6c6bf7c7d6d2d8e56c363\n' > $out/licenses/android-sdk-preview-license
    '';
  };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    jdk21
    gradle_8
  ];
  ANDROID_HOME = "${sdk}/libexec/android-sdk";
  ANDROID_SDK_ROOT = "${sdk}/libexec/android-sdk";
  JAVA_HOME = "${pkgs.jdk21}";
  # NixOS: aapt2 from Maven Central cannot run (glibc), use SDK's patched one.
  # Pass to gradle: -Pandroid.aapt2FromMavenOverride=$ANDROID_HOME/build-tools/36.1.0/aapt2
}
