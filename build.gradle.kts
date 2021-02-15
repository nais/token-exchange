import org.gradle.api.tasks.testing.logging.TestLogEvent
import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import org.jmailen.gradle.kotlinter.tasks.LintTask
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

val assertjVersion = "3.18.1"
val flywayVersion = "7.4.0"
val freemarkerVersion = "2.3.29"
val h2Version = "1.4.200"
val hikaricpVersion = "3.4.5"
val jacksonVersion = "2.10.1"
val junitJupiterVersion = "5.7.0"
val konfigVersion = "1.6.10.0"
val kotestVersion = "4.3.2"
val kotlinLoggingVersion = "2.0.4"
val kotlinVersion = "1.4.20"
val kotlintestVersion = "3.4.2"
val kotliqueryVersion = "1.3.1"
val ktorVersion = "1.5.0"
val logbackVersion = "1.2.3"
val mockOAuth2ServerVersion = "0.2.3"
val logstashLogbackEncoderVersion = "6.6"
val micrometerRegistryPrometheusVersion = "1.6.2"
val mockWebServerVersion = "4.9.0"
val mockkVersion = "1.10.4"
val nimbusSdkVersion = "8.30"
val postgresqlVersion = "42.2.18"
val testcontainersPostgresVersion = "1.15.1"

val mainClassKt = "io.nais.security.oauth2.TokenExchangeAppKt"

plugins {
    application
    kotlin("jvm") version "1.4.20"
    id("org.jmailen.kotlinter") version "3.3.0"
    id("com.github.johnrengelman.shadow") version "6.1.0"
    id("com.github.ben-manes.versions") version "0.36.0"
}

application {
    mainClassName = mainClassKt
}

java {
    sourceCompatibility = JavaVersion.VERSION_15
    targetCompatibility = JavaVersion.VERSION_15
}

apply(plugin = "org.jmailen.kotlinter")

repositories {
    mavenCentral()
    jcenter()
    maven(url = "https://dl.bintray.com/michaelbull/maven")
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("io.ktor:ktor-auth:$ktorVersion")
    implementation("io.ktor:ktor-auth-jwt:$ktorVersion")
    implementation("io.ktor:ktor-client-core:$ktorVersion")
    implementation("io.ktor:ktor-client-cio:$ktorVersion")
    implementation("io.ktor:ktor-client-json:$ktorVersion")
    implementation("io.ktor:ktor-client-jackson:$ktorVersion")
    implementation("com.natpryce:konfig:$konfigVersion")
    implementation("io.github.microutils:kotlin-logging:$kotlinLoggingVersion")
    implementation("io.ktor:ktor-metrics-micrometer:$ktorVersion")
    implementation("io.micrometer:micrometer-registry-prometheus:$micrometerRegistryPrometheusVersion")
    implementation("io.ktor:ktor-jackson:$ktorVersion")
    implementation("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    implementation("com.github.seratch:kotliquery:$kotliqueryVersion")
    implementation("com.zaxxer:HikariCP:$hikaricpVersion")
    implementation("org.postgresql:postgresql:$postgresqlVersion")
    implementation("org.flywaydb:flyway-core:$flywayVersion")
    runtimeOnly("ch.qos.logback:logback-classic:$logbackVersion")
    implementation("net.logstash.logback:logstash-logback-encoder:$logstashLogbackEncoderVersion")
    testImplementation("com.h2database:h2:$h2Version")
    testImplementation("no.nav.security:mock-oauth2-server:$mockOAuth2ServerVersion")
    testImplementation("org.assertj:assertj-core:$assertjVersion")
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testImplementation("io.ktor:ktor-client-mock-jvm:$ktorVersion")
    testImplementation("com.squareup.okhttp3:mockwebserver:$mockWebServerVersion")
    testImplementation("io.mockk:mockk:$mockkVersion")
    testImplementation("io.kotest:kotest-runner-junit5-jvm:$kotestVersion") // for kotest framework
    testImplementation("io.kotest:kotest-assertions-core-jvm:$kotestVersion") // for kotest core jvm assertions
    testImplementation("io.kotest:kotest-property-jvm:$kotestVersion") // for kotest property test
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitJupiterVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:$kotlinVersion")
    testImplementation("org.testcontainers:postgresql:$testcontainersPostgresVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitJupiterVersion")

}

tasks {
    withType<LintTask> {
        dependsOn("formatKotlin")
    }
    withType<ShadowJar> {
        archiveBaseName.set("app")
        archiveClassifier.set("")
        manifest {
            attributes(
                mapOf(
                    "Main-Class" to mainClassKt
                )
            )
        }
    }

    withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "15"
        }
    }

    withType<Test> {
        useJUnitPlatform()
        testLogging {
            events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED)
        }
    }

    withType<Wrapper> {
        gradleVersion = "6.7.1"
    }

    "build" {
        dependsOn("shadowJar")
    }
}
