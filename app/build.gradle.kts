plugins {
    id("com.android.application")
}

val releaseSigningStoreFile = System.getenv("ANDROID_SIGNING_STORE_FILE")
val releaseSigningStorePassword = System.getenv("ANDROID_SIGNING_STORE_PASSWORD")
val releaseSigningKeyAlias = System.getenv("ANDROID_SIGNING_KEY_ALIAS")
val releaseSigningKeyPassword = System.getenv("ANDROID_SIGNING_KEY_PASSWORD")
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
        versionCode = 1
        versionName = "0.2.0"
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
