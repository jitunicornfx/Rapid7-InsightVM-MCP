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

// The server version is declared in two places: `version` above, which names the release and the
// JAR, and SERVER_VERSION in McpServerFactory.kt, which is what the MCP Implementation block, the
// startup banner, the outbound User-Agent and — critically — the update comparison report. If those
// drift, a release ships a JAR that reports a different version than it is; and because
// UpdateChecker compares GitHub's latest release against SERVER_VERSION, the server would see its
// own release as newer and reinstall it on every start. This check makes that state unreleasable.
val verifyServerVersion = tasks.register("verifyServerVersion") {
    group = "verification"
    description = "Fails if SERVER_VERSION in McpServerFactory.kt disagrees with the project version."

    val projectVersion = project.version.toString()
    val factory = layout.projectDirectory.file(
        "src/main/kotlin/com/jitunicornfx/insightvm/mcp/McpServerFactory.kt",
    )
    val marker = layout.buildDirectory.file("verification/server-version-ok.txt")

    inputs.property("version", projectVersion)
    inputs.file(factory)
    // A marker output keeps the task up to date when neither the version nor the file has changed.
    outputs.file(marker)

    doLast {
        // The trailing quote is not part of the pattern: [^"]+ already stops at it, which keeps this
        // a raw string and avoids escaping backslashes.
        val declared = Regex("""const\s+val\s+SERVER_VERSION\s*=\s*"([^"]+)""")
            .find(factory.asFile.readText())?.groupValues?.get(1)
            ?: throw GradleException(
                "Could not find a `const val SERVER_VERSION = ...` declaration in " +
                    "${factory.asFile.name}. If it changed shape, update verifyServerVersion to match.",
            )
        if (declared != projectVersion) {
            throw GradleException(
                "Server version mismatch: build.gradle.kts declares $projectVersion but " +
                    "${factory.asFile.name} declares SERVER_VERSION = $declared. Set both to the same " +
                    "value before releasing — a JAR that misreports its version makes the update check " +
                    "treat its own release as newer and reinstall it on every start.",
            )
        }
        marker.get().asFile.apply { parentFile.mkdirs() }.writeText(projectVersion + System.lineSeparator())
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification, verifyCatalog, verifyServerVersion)
}

// The plain jar holds only this project's classes — it has no dependencies and is not runnable.
// Give it an explicit classifier so it cannot be mistaken for the launcher ("no main manifest attribute").
tasks.jar {
    archiveClassifier.set("thin")
}

tasks.shadowJar {
    // `./gradlew shadowJar` (the documented build command) does not run `check`, so the
    // release artifact itself has to depend on the version check.
    dependsOn(verifyServerVersion)
    archiveBaseName.set("rapid7-insightvm-mcp")
    archiveClassifier.set("all")
    archiveVersion.set(project.version.toString())
    mergeServiceFiles()
    manifest {
        // JNA (pulled in by kotlinx-io/ktor) loads native code; JDK 24+ warns unless the launcher jar opts in.
        attributes("Enable-Native-Access" to "ALL-UNNAMED")
    }
}
