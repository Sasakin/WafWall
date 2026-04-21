plugins {
    java
    id("org.springframework.boot") version "3.2.0" apply false
}

allprojects {
    group = "com.waf"
    version = "1.0.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "java")

    java {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }
}

project(":gateway") {
    apply(plugin = "org.springframework.boot")
    tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
        archiveFileName.set("gateway.jar")
    }
}

project(":processor") {
    apply(plugin = "org.springframework.boot")
    tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
        archiveFileName.set("processor.jar")
    }
}

project(":alert") {
    apply(plugin = "org.springframework.boot")
    tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
        archiveFileName.set("alert.jar")
    }
}