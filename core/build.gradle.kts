plugins {
    kotlin("jvm")
    `java-library`
}

repositories { mavenCentral() }

dependencies {
    // The oldest stdlib and coroutines this compiles against, not the newest:
    // a consumer on a later Kotlin resolves to its own.
    api("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // Stamp metadata a Kotlin 2.0 consumer (AGP's built-in Kotlin) can read.
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
