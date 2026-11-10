// Standalone build (CI); apps include :pushir with their own plugin versions.
// AGP's built-in Kotlin, at the latest compiler.
buildscript { dependencies { classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21") } }

plugins {
    id("com.android.library") version "9.5.1" apply false
}
