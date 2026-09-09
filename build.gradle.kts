import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.shadow)
    application
    jacoco
}

group = "com.jitunicornfx.insightvm"
version = "0.2.0"

dependencies {
    implementation(platform(libs.ktor.bom))

    implementation(libs.mcp.kotlin.server)

    // Command-line interface.
    implementation(libs.clikt)

    // HTTP client used to talk to the InsightVM REST APIs. OkHttp (blocking sockets, its own thread
    // pool) rather than CIO: CIO's NIO selector opens a loopback self-pipe (an AF_UNIX socket on
    // recent JDKs) that some locked-down Windows/EDR hosts refuse, crashing the HTTP layer at startup.
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.okhttp)

    // Only required for the optional --http (Streamable HTTP / SSE) transport.
    implementation(libs.ktor.server.cio)
    implementation(libs.ktor.server.cors)

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)

    // slf4j-simple logs to stderr by default, which keeps stdout clean for the
    // MCP JSON-RPC channel when running over stdio.
    implementation(libs.slf4j.simple)

    testImplementation(kotlin("test"))
    testImplementation(libs.mcp.kotlin.client)
    // Ktor MockEngine lets tests drive the tool handlers without real network calls.
    testImplementation(libs.ktor.client.mock)
    testImplementation(libs.ktor.server.test.host)

    testImplementation(platform(libs.junit.bom))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass.set("com.jitunicornfx.insightvm.mcp.MainKt")
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_21
        javaParameters = true
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

jacoco {
    toolVersion = "0.8.15"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }
}

// Coverage gate: the build fails below 90% line coverage.
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.90".toBigDecimal()
            }
        }
    }
}

// The tool catalog under src/main/resources/catalog is generated from specs/ by CatalogGenerator
// (src/main/kotlin/.../catalog/CatalogGenerator.kt). `generateCatalog` rewrites it; `verifyCatalog`
// (part of `check`) fails if the committed copy has drifted from the specifications.
val generatorMain = "com.jitunicornfx.insightvm.mcp.catalog.CatalogGenerator"

val generateCatalog = tasks.register<JavaExec>("generateCatalog") {
    group = "build"
    description = "Regenerates src/main/resources/catalog from specs/."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set(generatorMain)
    workingDir = projectDir
}

val verifyCatalog = tasks.register<JavaExec>("verifyCatalog") {
    group = "verification"
    description = "Fails if src/main/resources/catalog is out of date with specs/ (skipped when specs/ is absent)."
    // The OpenAPI documents are not part of the repository; the drift check only makes sense where they exist.
    onlyIf { file("specs").isDirectory }
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set(generatorMain)
    args("--check")
    workingDir = projectDir
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification, verifyCatalog)
}

// The plain jar holds only this project's classes — it has no dependencies and is not runnable.
// Give it an explicit classifier so it cannot be mistaken for the launcher ("no main manifest attribute").
tasks.jar {
    archiveClassifier.set("thin")
}

tasks.shadowJar {
    archiveBaseName.set("rapid7-insightvm-mcp")
    archiveClassifier.set("all")
    archiveVersion.set(project.version.toString())
    mergeServiceFiles()
    manifest {
        // JNA (pulled in by kotlinx-io/ktor) loads native code; JDK 24+ warns unless the launcher jar opts in.
        attributes("Enable-Native-Access" to "ALL-UNNAMED")
    }
}
