import java.util.Properties

plugins {
    id("com.android.application")
}

// Local signing. Password/key alias come from the gitignored local.properties,
// overridden by the ANDROID_SIGNING_* env vars that GitHub Actions sets. The
// keystore ships at F:/Key/ABK_Fido, so no env var is needed for a local build.
val signingProperties = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
val releaseSigningStoreFile = System.getenv("ANDROID_SIGNING_STORE_FILE")
    ?: "F:\\Key\\ABK_Fido"
val releaseSigningStorePassword = System.getenv("ANDROID_SIGNING_STORE_PASSWORD")
    ?: signingProperties.getProperty("abk.storePassword")
val releaseSigningKeyAlias = System.getenv("ANDROID_SIGNING_KEY_ALIAS")
    ?: signingProperties.getProperty("abk.keyAlias")
val releaseSigningKeyPassword = System.getenv("ANDROID_SIGNING_KEY_PASSWORD")
    ?: signingProperties.getProperty("abk.keyPassword")
val hasReleaseSigning = listOf(
    releaseSigningStoreFile,
    releaseSigningStorePassword,
    releaseSigningKeyAlias,
    releaseSigningKeyPassword,
).all { !it.isNullOrBlank() }

android {
    namespace = "com.abk.extension.fido"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.abk.extension.fido"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.4.0"
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(releaseSigningStoreFile!!)
                storePassword = releaseSigningStorePassword
                keyAlias = releaseSigningKeyAlias
                keyPassword = releaseSigningKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = false
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("com.github.topjohnwu.libsu:core:5.2.2")
    // Android 14+ Credential Manager provider bridge used by browser/passkey flows.
    implementation("androidx.credentials:credentials:1.5.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.5.0")

    testImplementation("junit:junit:4.13.2")
}
