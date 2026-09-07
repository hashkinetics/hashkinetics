# HashKinetics Wallet — Android (WA2)

Kotlin + Jetpack Compose over the Rust wallet core (`chain/crates/hk-wallet-core`, UniFFI). The app holds no
protocol logic: every operation is one call into the core, which writes the same `account.json` /
`shield.json` / `disclosure-*.json` the desktop wallet and `hk-node account-*` use — sealed at rest with the
same `HKE1` envelope (phone-sized Argon2id profile) when a passphrase is set.

## Build (first time)

1. Rust core for Android (WSL):
   ```bash
   cd chain
   ./android-core.sh setup                      # rust targets + cargo-ndk; prints how to get NDK r27
   export ANDROID_NDK_HOME=~/android/android-ndk-r27c
   ./android-core.sh all                        # → android/core-out/jniLibs/{arm64-v8a,x86_64}/libhk_wallet_core.so + kotlin/org/hashkinetics/wallet/core/hk_wallet_core.kt
   cp -r ../android/core-out/jniLibs ../android/app/src/main/
   mkdir -p ../android/app/src/main/java/org/hashkinetics/wallet/core && cp ../android/core-out/kotlin/org/hashkinetics/wallet/core/*.kt ../android/app/src/main/java/org/hashkinetics/wallet/core/
   ```
2. App (Android Studio, Windows or Linux): File → Open → `android/` (this folder), let Gradle sync — the wrapper
   properties pin Gradle 8.9; AGP 8.6.1, Kotlin 2.0.20, compose BOM 2024.09 come from the build files; the SDK
   manager installs API 35 + build-tools on first sync. Run ▶ on a USB phone (arm64-v8a, USB debugging on) or an
   x86_64 emulator image (API 30+ recommended). Debug builds talk to testnet-1's public endpoints.
   Without the IDE (WSL): `sdkmanager "platforms;android-35" "build-tools;35.0.0"` from the command-line tools,
   then `gradle wrapper && ./gradlew assembleDebug` → `app/build/outputs/apk/debug/app-debug.apk` (sideload).

## What it does (v0.1)

Create / restore a keychain · balance + fee + height · faucet · transparent send · shielded: stealth address,
scan (incremental, cached in `shield.json`), shield / unshield / pay with memo / disclose · backup: seed once,
passphrase (Argon2id 256 MiB, sealed files), optional device lock (a 32-byte key file wrapped by the Android
Keystore — the sealed files then need this device or the exported key file; off by default so a phone backup
restores on a PC with the passphrase alone) · activity log with explorer links.

## What it does NOT do (yet)

No in-app proving (proofs are made on the public prover; a shielded operation takes a minute or two), no
QR scanning of addresses (v0.2), no biometric release of the key file (v0.2: `setUserAuthenticationRequired`),
no push notifications, no iOS. Unaudited testnet software; nothing is for sale.

## Files on the phone

`filesDir/wallet/account.json`, `…/shield.json`, `…/disclosure-*.json` (byte-compatible with the desktop wallet);
`filesDir/keyfile.bin` (device lock: IV ‖ AES-GCM ciphertext of the 32-byte key file, key in the Android Keystore).
`android:allowBackup="false"` — the wallet files never ride a cloud backup; the user exports them.
