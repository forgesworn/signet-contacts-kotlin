plugins {
    kotlin("jvm")
    `java-library`
}

repositories { mavenCentral() }

dependencies {
    api(project(":signet-contacts"))
    // The API half only. A consumer adds the native half for its platform:
    // secp256k1-kmp-jni-android on Android, secp256k1-kmp-jni-jvm on a desktop JVM.
    api("fr.acinq.secp256k1:secp256k1-kmp-jvm:0.19.0")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.19.0")
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_0)
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_0)
    }
}

java {
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.test {
    useJUnitPlatform()
    val vectors = rootProject.file(findProperty("signetContactsVectors") as String)
    systemProperty("signetContacts.vectors", vectors.canonicalPath)
}

// secp256k1-kmp-jni-jvm (tests only) publishes for JVM 21. The library itself
// still targets 17: the API artefact it depends on is Java 8 bytecode, and an
// Android consumer uses secp256k1-kmp-jni-android instead.
listOf("testCompileClasspath", "testRuntimeClasspath").forEach { name ->
    configurations.named(name) {
        attributes { attribute(TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE, 21) }
    }
}
