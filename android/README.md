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

## What it does (v0.2)

Four sections behind a bottom bar, in the brand theme (`app/src/main/java/org/hashkinetics/wallet/ui/Theme.kt` —
the site's engineering-dark palette; the launcher icon is the brand mark drawn as vector paths):

- **Wallet** — balance + fee + height, faucet, receive (account id with a QR + copy), transparent send.
- **Shielded** — hidden balance, stealth address (QR + copy), scan (incremental, cached in `shield.json`), notes,
  shield / unshield / pay with a memo / disclose one payment.
- **Backup** — seed once, passphrase (Argon2id 256 MiB, sealed files), optional device lock (a 32-byte key file
  wrapped by the Android Keystore — the sealed files then need this device or the exported key file; off by default
  so a phone backup restores on a PC with the passphrase alone).
- **Activity** — every core call's report, with explorer links.

Before a wallet exists: Welcome (create / restore). While the files are sealed: Unlock. The chain is read on open.

## What it does NOT do (yet)

No in-app proving (proofs are made on the public prover; a shielded operation takes a minute or two), no
QR *scanning* of addresses (the camera; v0.3), no biometric release of the key file (v0.3: `setUserAuthenticationRequired`),
no push notifications, no iOS. Unaudited testnet software; nothing is for sale.

## Release signing (WA3)

The release key is **not in this tree**. `app/build.gradle.kts` reads `HK_ANDROID_KEYSTORE` (a path),
`HK_ANDROID_KEYSTORE_PASSWORD`, `HK_ANDROID_KEY_ALIAS`, `HK_ANDROID_KEY_PASSWORD` from the environment; CI
(`.github/workflows/wallet-android.yml`) decodes the keystore from the repository secret `HK_ANDROID_KEYSTORE_B64`
into a temp file for the one Gradle step and ships a release-signed `HashKinetics-Wallet-android-<version>.apk`
with its sha256 and the signer's certificate digest (`apksigner verify --print-certs`). Without the secrets
(forks, pull requests, a developer machine) the build falls back to the local debug key and the artifact is named
`-debug`: it runs, but Android will not upgrade it over a published build (uninstall first — that deletes the
wallet files on the phone).

Releases are tag-first and immutable: `wallet-android-vX.Y.Z` must equal `versionName` (the workflow checks),
the tag's run produces the artifact, the APK + `.sha256` are attached to the GitHub release by hand, and the row
goes into `networks/testnet-1/CHECKSUMS`. Verify a download with `sha256sum` / `Get-FileHash`, and the signer
with `apksigner verify --print-certs HashKinetics-Wallet-android-<version>.apk` (the digest is in the release
text). Losing the key means every future build is a different app to Android — the keystore and its passphrase
are backed up off the fleet like the treasury passphrase.

## Files on the phone

`filesDir/wallet/account.json`, `…/shield.json`, `…/disclosure-*.json` (byte-compatible with the desktop wallet);
`filesDir/keyfile.bin` (device lock: IV ‖ AES-GCM ciphertext of the 32-byte key file, key in the Android Keystore).
`android:allowBackup="false"` — the wallet files never ride a cloud backup; the user exports them.
