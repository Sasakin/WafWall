plugins {
    java
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    compileOnly("org.projectlombok:lombok:1.18.30")
    annotationProcessor("org.projectlombok:lombok:1.18.30")
    implementation(project(":common"))
    implementation("org.springframework.boot:spring-boot-starter-web:3.2.0")
    implementation("org.apache.httpcomponents.client5:httpclient5:5.3.1")
    implementation("org.springframework.boot:spring-boot-starter-data-redis:3.2.0")
    implementation("org.springframework.kafka:spring-kafka:3.2.0")
    implementation("io.micrometer:micrometer-registry-prometheus:1.12.0")
    implementation("org.springframework.boot:spring-boot-starter-actuator:3.2.0")
    implementation("org.yaml:snakeyaml:2.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.16.0")
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.8")
    implementation("io.github.resilience4j:resilience4j-spring-boot2:2.2.0")
}