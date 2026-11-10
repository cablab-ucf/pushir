// Kotlin only: the app links the pushir crate (feature `jni`) into its own
// native library and names it in Pushir.start.
plugins {
    id("com.android.library") // AGP 9: Kotlin is built in
}

android {
    namespace = "org.pushir"
    compileSdk = 37
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
