plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.hashkinetics.wallet"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.hashkinetics.wallet"
        minSdk = 26            // Argon2id at 256 MiB + ML-KEM want a 64-bit device; 26 = Android 8.0
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"  // shown next to the core's own CORE_VERSION
        ndk {
            // the Rust core ships for these two only (chain/android-core.sh): phones + the emulator
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false // keep the UniFFI/JNA symbols untouched for the first releases
            signingConfig = signingConfigs.getByName("debug") // WA3: a release key kept out of the tree
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    packaging {
        // the .so files come from chain/android-core.sh → app/src/main/jniLibs/<abi>/libhk_wallet_core.so
        jniLibs { useLegacyPackaging = false }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    // UniFFI's Kotlin bindings load the cdylib through JNA (the @aar carries the Android natives).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // QR of the account id on the Receive screen.
    implementation("com.google.zxing:core:3.5.3")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
