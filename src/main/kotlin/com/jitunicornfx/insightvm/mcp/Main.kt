package com.jitunicornfx.insightvm.mcp

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.help
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.switch
import com.github.ajalt.clikt.parameters.types.choice
import com.github.ajalt.clikt.parameters.types.int
import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.CatalogFilter
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.PagingDefaults
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.routing
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerSession
import io.modelcontextprotocol.kotlin.sdk.server.StdioServerTransport
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.asSink
import kotlinx.io.asSource
import kotlinx.io.buffered
import java.io.File
import java.io.InputStream
import java.io.PrintStream
import java.util.concurrent.atomic.AtomicBoolean

const val DEFAULT_HTTP_HOST = "127.0.0.1"
const val DEFAULT_HTTP_PORT = 3072
const val STREAMABLE_HTTP_PATH = "/mcp"
const val LEGACY_SSE_PATH = "/sse"

/** Guards [autoInstall] so a release is downloaded and installed at most once per process. */
private val installAttempted = AtomicBoolean(false)

internal enum class Transport { STDIO, HTTP }

/**
 * Command-line entry point for the Rapid7 InsightVM MCP server (built with Clikt).
 *
 * Transports:
 *  - `--stdio` (default): standard MCP stdio transport for local desktop clients.
 *  - `--http`: Streamable HTTP / SSE transport, bound to `--host`/`--port` (default port 3072).
 *
 * All diagnostics are written to stderr so stdout stays reserved for the JSON-RPC channel.
 *
 * The [configProvider] and [serve] seams exist so tests can drive option parsing and the run()
 * dispatch without reading the real environment or starting a (blocking) server.
 */
class Rapid7InsightVmCommand internal constructor(
    private val configProvider: () -> Config,
    private val serve: (transport: Transport, host: String, port: Int, config: Config) -> Unit,
) : CliktCommand(name = "rapid7-insightvm-mcp") {

    /** Production entry point: reads config from the environment and starts a real server. */
    constructor() : this({ Config.fromEnv() }, ::runServer)

    override fun help(context: Context): String =
        "Run the Rapid7 InsightVM MCP server over stdio (default) or Streamable HTTP/SSE."

    override fun helpEpilog(context: Context): String =
        """
        |Environment variables (at least one API must be configured):
        |
        |${Config.ENV_CONSOLE_URL}, ${Config.ENV_CONSOLE_USERNAME}, ${Config.ENV_CONSOLE_PASSWORD}: Security Console API v3 (https://host:3780).
        |
        |${Config.ENV_CONSOLE_2FA_TOKEN} (optional): the two-factor code sent in the Token header. It is time-based and stops working within about a minute; prefer an account without two-factor authentication.
        |
        |${Config.ENV_CONSOLE_CA_CERT} (optional): PEM file with the console's CA/self-signed certificate.
        |
        |${Config.ENV_CONSOLE_INSECURE_TLS} (optional): 1 disables TLS verification for the console (lab use only).
        |
        |${Config.ENV_ALLOW_HTTP} (optional): 1 permits cleartext http:// API URLs (lab use only).
        |
        |${Config.ENV_API_KEY}, ${Config.ENV_REGION}: Insight Platform Cloud Integrations API v4 (regions: ${Region.entries.joinToString(", ") { it.code }}).
        |
        |${Config.ENV_MCP_AUTH_TOKEN}: bearer token required by --http (mandatory, and at least ${HttpSecurity.MIN_TOKEN_LENGTH} characters, when --host is not loopback).
        |
        |${Config.ENV_HTTP_ALLOWED_ORIGINS} (optional): comma-separated browser origins allowed in --http mode.
        |
        |${Config.ENV_READ_ONLY}, ${Config.ENV_TAGS}, ${Config.ENV_EXCLUDE_TAGS}, ${Config.ENV_ALLOW_ADMIN_COMMANDS}, ${Config.ENV_ALLOW_SECRET_TOOLS}: tool filters (same as the flags).
        |
        |${Config.ENV_TIMEOUT_MS} (default ${Config.DEFAULT_TIMEOUT_MS}), ${Config.ENV_MAX_RESPONSE_BYTES} (default ${Config.DEFAULT_MAX_RESPONSE_BYTES}, a memory guard on the wire).
        |
        |${Config.ENV_MAX_RESULT_CHARS} (optional): characters of API data one tool result may carry, default ${Config.DEFAULT_MAX_RESULT_CHARS} (~50k tokens). This is the model-context budget.
        |
        |${Config.ENV_KEEP_RECORD_LINKS} (optional): 1 keeps the per-record HATEOAS 'links' that are stripped by default (they are ~93% of a large reference list).
        |
        |${Config.ENV_DEFAULT_PAGE_SIZE} (optional): 'size' injected when a paged tool is called without one, default ${PagingDefaults.DEFAULT_PAGE_SIZE}, clamped to ${PagingDefaults.MAX_PAGE_SIZE}.
        |
        |${Config.ENV_SPOOL_DIR} (optional): where insightvm_export_to_file writes, default ~/.rapid7-insightvm-mcp/spool. ${Config.ENV_SPOOL_RETENTION_HOURS} (default ${Config.DEFAULT_SPOOL_RETENTION_HOURS}h, 0 never sweeps).
        |
        |${Config.ENV_DISABLE_EXPORT} (optional): 1 removes insightvm_export_to_file, the only tool that writes to the local filesystem.
        |
        |${Config.ENV_DISABLE_UPDATE_CHECK}, ${Config.ENV_DISABLE_AUTO_UPDATE}: update behaviour (see --no-update-check / --no-auto-update).
        """.trimMargin()

    private val transport: Transport by option()
        .switch("--stdio" to Transport.STDIO, "--http" to Transport.HTTP)
        .default(Transport.STDIO)
        .help("Transport to run. Defaults to --stdio.")

    private val host: String by option("--host", "--ip")
        .default(DEFAULT_HTTP_HOST)
        .help("Address to listen on in HTTP mode. Defaults to $DEFAULT_HTTP_HOST.")

    private val port: Int by option("--port")
        .int()
        .default(DEFAULT_HTTP_PORT)
        .help("Port to listen on in HTTP mode. Defaults to $DEFAULT_HTTP_PORT.")

    private val readOnly: Boolean by option("--read-only")
        .flag(default = false)
        .help("Register only read-only tools: every GET, plus the five query-only POST searches. Equivalent to ${Config.ENV_READ_ONLY}=1.")

    private val tags: List<String> by option("--tags")
        .multiple()
        .help("Comma-separated API tags to expose (e.g. Site,Asset,Vulnerability). Repeatable.")

    private val excludeTags: List<String> by option("--exclude-tags")
        .multiple()
        .help("Comma-separated API tags to hide. Repeatable.")

    private val api: String? by option("--api")
        .choice("console", "cloud", "both")
        .help("Which configured API family to expose. Defaults to every configured family.")

    private val tools: List<String> by option("--tools")
        .multiple()
        .help("Glob on tool names (e.g. 'get_site*'). Repeatable; a tool is kept if any glob matches.")

    private val allowAdminCommands: Boolean by option("--allow-admin-commands")
        .flag(default = false)
        .help(
            "Register execute_command (POST /api/3/administration/commands), which runs arbitrary " +
                "commands on the Security Console. Off by default. Equivalent to ${Config.ENV_ALLOW_ADMIN_COMMANDS}=1.",
        )

    private val allowSecretTools: Boolean by option("--allow-secret-tools")
        .flag(default = false)
        .help(
            "Register the six tools that return or set authentication secrets: a user's two-factor seed (read, " +
                "regenerate, set), a user's password, and the scan-engine pairing secret (read, create). Off by default, " +
                "including under --read-only. Equivalent to ${Config.ENV_ALLOW_SECRET_TOOLS}=1.",
        )

    private val noAutoUpdate: Boolean by option("--no-auto-update")
        .flag(default = false)
        .help("Never download or install a new release; only report that one is available. Equivalent to ${Config.ENV_DISABLE_AUTO_UPDATE}=1.")

    private val noUpdateCheck: Boolean by option("--no-update-check")
        .flag(default = false)
        .help("Skip the startup check for a newer release entirely (implies --no-auto-update). Equivalent to ${Config.ENV_DISABLE_UPDATE_CHECK}=1.")

    override fun run() {
        val fromEnv = try {
            configProvider()
        } catch (e: Exception) {
            echo("Configuration error: ${e.message}", err = true)
            throw ProgramResult(1)
        }

        val families = when (api) {
            "console" -> setOf(ApiFamily.CONSOLE)
            "cloud" -> setOf(ApiFamily.CLOUD)
            else -> ApiFamily.entries.toSet()
        }
        val cliFilter = ToolFilter(
            readOnly = readOnly,
            tags = tags.flatMap { Config.csv(it) }.toSet(),
            excludeTags = excludeTags.flatMap { Config.csv(it) }.toSet(),
            // The only two flags that loosen the environment: each opens one named gate, is explicit, and
            // is logged at startup and reported by insightvm_server_info.
            allowAdminCommands = fromEnv.filter.allowAdminCommands || allowAdminCommands,
            allowSecretTools = fromEnv.filter.allowSecretTools || allowSecretTools,
            families = families,
            nameGlobs = tools.flatMap { Config.csv(it) },
        )
        val filter = fromEnv.filter.tighten(cliFilter)
            .copy(allowAdminCommands = cliFilter.allowAdminCommands, allowSecretTools = cliFilter.allowSecretTools)

        val config = fromEnv.copy(
            filter = filter,
            updateCheckDisabled = fromEnv.updateCheckDisabled || noUpdateCheck,
            autoUpdateDisabled = fromEnv.autoUpdateDisabled || noAutoUpdate || noUpdateCheck,
        )

        if (config.activeFamilies.isEmpty()) {
            echo("Configuration error: --api ${api ?: "both"} selected but that API family is not configured.", err = true)
            throw ProgramResult(1)
        }
        // The merged filter holds only the tags common to both lists, so check the values as given.
        checkToolSelection(config, requestedTags = fromEnv.filter.tags + cliFilter.tags)
        if (transport == Transport.HTTP) checkBearerToken(config.httpAuthToken)
        // Said once at startup as well as in every console 401 hint: the failure only shows up a minute
        // later, far from the configuration that caused it.
        if (config.console?.twoFactorToken != null) {
            echo("[insightvm-mcp] WARNING: ${Config.TWO_FACTOR_TOKEN_NOTE}", err = true)
        }
        serve(transport, host, port, config)
    }

    /**
     * Refuse filters that leave no API tool at all, and warn about each filter value that matches
     * nothing. A tag typo (`Sites` for `Site`), env and command-line tag lists with nothing in common,
     * or a mistyped glob used to start a server that offered only the meta tools, and the single
     * "registered 0/343" line on stderr was easy to miss: desktop clients rarely surface stderr.
     *
     * Values are checked against the catalogs of the active families on their own, not after the
     * other filters, so a warning always means "this value is wrong", never "this combination is".
     */
    private fun checkToolSelection(config: Config, requestedTags: Set<String>) {
        val catalogs = CatalogLoader.loadAll(config.activeFamilies)
        val filter = config.filter
        val unknownTags = CatalogFilter.unknownTags(catalogs, requestedTags)
        val unknownExcluded = CatalogFilter.unknownTags(catalogs, filter.excludeTags)
        unknownTags.forEach {
            echo("[insightvm-mcp] WARNING: --tags / ${Config.ENV_TAGS} value '$it' matches no tag of the selected APIs.", err = true)
        }
        unknownExcluded.forEach {
            echo(
                "[insightvm-mcp] WARNING: --exclude-tags / ${Config.ENV_EXCLUDE_TAGS} value '$it' matches no tag of the " +
                    "selected APIs, so it hides nothing.",
                err = true,
            )
        }
        CatalogFilter.unmatchedGlobs(catalogs, filter.nameGlobs).forEach {
            echo("[insightvm-mcp] WARNING: --tools glob '$it' matches no tool name.", err = true)
        }
        // A glob naming a gated tool is not a typo, so it would otherwise register nothing in silence.
        if (!filter.allowSecretTools) {
            CatalogFilter.secretOnlyGlobs(catalogs, filter.nameGlobs).forEach {
                echo(
                    "[insightvm-mcp] WARNING: --tools glob '$it' names only tools that return or set authentication " +
                        "secrets, which are registered only with --allow-secret-tools / ${Config.ENV_ALLOW_SECRET_TOOLS}=1.",
                    err = true,
                )
            }
        }

        val validTags = "Valid tags: ${CatalogFilter.tags(catalogs).joinToString(", ")}."
        if (CatalogFilter.select(catalogs, filter.copy(families = config.activeFamilies)).isEmpty()) {
            val total = catalogs.values.sumOf { it.ops.size }
            val disjoint = if (ToolFilter.NO_TAGS_SENTINEL in filter.tags) {
                " ${Config.ENV_TAGS} and --tags have no tag in common, and the command line can only narrow the environment."
            } else {
                ""
            }
            echo(
                "Configuration error: the tool filters (read-only, tags, excluded tags, API family, tool globs) " +
                    "select none of the $total API tools.$disjoint $validTags",
                err = true,
            )
            throw ProgramResult(1)
        }
        if (unknownTags.isNotEmpty() || unknownExcluded.isNotEmpty()) echo("[insightvm-mcp] $validTags", err = true)
    }

    /**
     * On a non-loopback `--http` bind the bearer token is the only control between the network and the
     * InsightVM credentials, and the failure throttle is per client address, so guesses spread across
     * addresses are bounded only by the token's entropy. Refuse a missing or short one there; on
     * loopback, where only local processes can connect, a short one earns a warning.
     */
    private fun checkBearerToken(token: String?) {
        val short = token != null && token.length < HttpSecurity.MIN_TOKEN_LENGTH
        if (isLoopback(host)) {
            if (short) {
                echo(
                    "[insightvm-mcp] WARNING: ${Config.ENV_MCP_AUTH_TOKEN} is shorter than ${HttpSecurity.MIN_TOKEN_LENGTH} " +
                        "characters; generate one with `openssl rand -hex 32`.",
                    err = true,
                )
            }
            return
        }
        if (token == null) {
            echo(
                "Refusing to listen on $host without authentication: set ${Config.ENV_MCP_AUTH_TOKEN} " +
                    "to a strong shared secret, or bind to a loopback address.",
                err = true,
            )
            throw ProgramResult(2)
        }
        if (short) {
            echo(
                "Refusing to listen on $host with a weak ${Config.ENV_MCP_AUTH_TOKEN}: off loopback it must be at least " +
                    "${HttpSecurity.MIN_TOKEN_LENGTH} characters. Generate one with `openssl rand -hex 32`.",
                err = true,
            )
            throw ProgramResult(2)
        }
    }
}

fun main(args: Array<String>) {
    // Diagnostics first, before anything that can fail: when a desktop client reports "server
    // transport closed unexpectedly", these lines in its log are usually all there is to go on.
    System.err.println(startupBanner(args))
    try {
        Rapid7InsightVmCommand().main(args)
    } catch (e: Throwable) {
        // Clikt handles its own exits; anything else escaping here would otherwise die silently.
        System.err.println("[insightvm-mcp] FATAL: ${e::class.simpleName}: ${e.message}")
        e.printStackTrace(System.err)
        kotlin.system.exitProcess(1)
    }
}

/** Where this code was loaded from (the JAR path, or the classes directory during development). */
internal fun runningLocation(): String =
    runCatching { Rapid7InsightVmCommand::class.java.protectionDomain.codeSource.location.toURI().path }
        .getOrNull() ?: "unknown"

/**
 * One multi-line stderr banner with everything needed to diagnose a failed start: version, runtime,
 * launch location, arguments and which `INSIGHTVM_*` variables are present (names only — values are
 * never printed). Also warns when the thin (dependency-free) JAR is being run by mistake.
 */
internal fun startupBanner(args: Array<String>, env: Map<String, String> = System.getenv()): String {
    val location = runningLocation()
    val present = env.keys.filter { it.startsWith("INSIGHTVM_") }.sorted()
    return buildString {
        append("[insightvm-mcp] $SERVER_NAME $SERVER_VERSION starting")
        append(" - java ${System.getProperty("java.version")} (${System.getProperty("java.vendor")})")
        append(", ${System.getProperty("os.name")} ${System.getProperty("os.arch")}")
        append('\n')
        append("[insightvm-mcp] location: $location\n")
        append("[insightvm-mcp] args: ${if (args.isEmpty()) "(none)" else args.joinToString(" ")}\n")
        append("[insightvm-mcp] environment: ")
        append(if (present.isEmpty()) "no INSIGHTVM_* variables set" else present.joinToString(", "))
    }
}

/** Creates the shared client and dispatches to the selected transport. */
internal fun runServer(transport: Transport, host: String, port: Int, config: Config) {
    // Install before anything can serve a tool call. There is exactly one Config per process — the
    // --http path builds a fresh Server per connection but never a fresh Config — so one budget per
    // process is the right granularity.
    ResultBudget.install(ResultBudget(maxChars = config.maxResultChars))
    SpoolStore.install(SpoolStore.resolve(config.spoolDirectory))
    if (config.spoolRetentionHours > 0) {
        SpoolStore.active.sweepStale(config.spoolRetentionHours * 3_600_000L)
    }
    // Leftovers from an interrupted self-update (".new" staging files and ".bak") would otherwise
    // accumulate beside the JAR at ~20 MB each; sweep them before anything else. The ".update.lock"
    // and ".running" sidecars are deliberately left alone — see UpdateInstaller.withInstallLock.
    UpdateInstaller.runningJar()?.let { jar ->
        // Declared for this server's whole life, so another server's exit never rewrites the JAR
        // underneath it; see UpdateInstaller.holdRunningLock.
        if (!UpdateInstaller.holdRunningLock(jar)) {
            System.err.println(
                "[insightvm-mcp] Could not mark ${jar.name} as in use; an update applied by another server " +
                    "as it exits may break this one.",
            )
        }
        val removed = UpdateInstaller.cleanupStaleArtifacts(jar)
        if (removed.isNotEmpty()) System.err.println("[insightvm-mcp] Removed stale update files: ${removed.joinToString(", ")}")
    }
    val client = Rapid7Client(config)
    Runtime.getRuntime().addShutdownHook(Thread { runCatching { client.close() } })

    when (transport) {
        Transport.STDIO -> {
            // In stdio mode stdout carries the JSON-RPC stream. Capture the real stdout for the
            // transport and redirect System.out to stderr so stray writes can't corrupt the channel.
            val protocolOut: PrintStream = System.out
            System.setOut(System.err)
            runStdio(client, config, protocolOut)
        }

        Transport.HTTP -> runHttp(client, config, host, port)
    }
}

private fun describeConfig(config: Config): String = buildString {
    config.console?.let { append("console=${it.baseUrl}") }
    config.cloud?.let { if (isNotEmpty()) append(", "); append("cloud=${it.region.code} (${it.baseUrl})") }
}

private fun logRegistration(built: BuiltServer) {
    System.err.println("[insightvm-mcp] ${built.summary}")
    if (built.selected.size > LARGE_TOOL_SET_THRESHOLD) {
        System.err.println(
            "[insightvm-mcp] ${built.selected.size} tools is a large set for some MCP clients; consider " +
                "--read-only, --tags, --api or --tools to trim it.",
        )
    }
}

/** Start the GitHub update check concurrently with startup, or return null when it is disabled. */
private fun CoroutineScope.startUpdateCheck(config: Config): Deferred<UpdateChecker.Result>? =
    if (config.updateCheckDisabled) {
        System.err.println("[insightvm-mcp] Update check disabled via ${Config.ENV_DISABLE_UPDATE_CHECK}.")
        null
    } else {
        async(Dispatchers.IO) { UpdateChecker.check() }
    }

/** Attach the deferred update result to a session, notifying the client once it is initialized. */
private fun CoroutineScope.notifyWhenInitialized(
    server: Server,
    session: ServerSession,
    updateCheck: Deferred<UpdateChecker.Result>?,
    config: Config,
) {
    if (updateCheck == null) return
    session.onInitialized {
        launch {
            val result = runCatching { updateCheck.await() }.getOrNull() ?: return@launch
            if (result.updateAvailable) System.err.println("[insightvm-mcp] ${result.message()}")
            server.notifyUpdateAvailable(session, result)
            if (result.updateAvailable) {
                val outcome = autoInstall(config, result)
                if (outcome != null) server.notifyUpdateInstalled(session, outcome)
            }
        }
    }
}

/**
 * Download and install [result]'s release, unless automatic installation is switched off.
 * Returns null when nothing was attempted.
 */
private suspend fun autoInstall(config: Config, result: UpdateChecker.Result): UpdateInstaller.Outcome? {
    if (!installAttempted.compareAndSet(false, true)) return null
    if (config.autoUpdateDisabled) {
        System.err.println(
            "[insightvm-mcp] Automatic installation is disabled (${Config.ENV_DISABLE_AUTO_UPDATE} / --no-auto-update); update it manually.",
        )
        return null
    }
    val outcome = UpdateInstaller.install(result)
    when (outcome) {
        is UpdateInstaller.Outcome.Installed ->
            System.err.println("[insightvm-mcp] Installed ${outcome.version}; restart to run it.")

        is UpdateInstaller.Outcome.Staged -> {
            System.err.println("[insightvm-mcp] Staged ${outcome.version}; it will be applied as this server exits.")
            val staged = File(outcome.stagedPath)
            val target = UpdateInstaller.runningJar()
            if (target != null) {
                // The stage has to survive until this process exits, which can be days away, while
                // every sibling started meanwhile sweeps old stages; see keepStagedFresh.
                val keepAlive = UpdateInstaller.keepStagedFresh(staged) {
                    System.err.println(
                        "[insightvm-mcp] Staged ${outcome.version} has been removed from disk and will NOT be " +
                            "applied as this server exits. It will be downloaded again on the next check.",
                    )
                }
                runCatching {
                    Runtime.getRuntime().addShutdownHook(
                        Thread {
                            // First: on Windows the keep-alive holds the stage open, which would block
                            // the swap's own delete of it.
                            runCatching { keepAlive.close() }
                            runCatching {
                                UpdateInstaller.installStagedAtShutdown(staged, target, outcome.sha256, outcome.targetSha256)
                            }
                        },
                    )
                }.onFailure {
                    runCatching { keepAlive.close() }
                    System.err.println(
                        "[insightvm-mcp] Shutting down already; ${outcome.version} remains staged at " +
                            "${outcome.stagedPath} and will not be applied automatically.",
                    )
                }
            }
        }

        is UpdateInstaller.Outcome.Failed ->
            System.err.println("[insightvm-mcp] Automatic update did not complete: ${outcome.reason}")

        UpdateInstaller.Outcome.Skipped -> Unit
    }
    return outcome
}

/**
 * Serve one MCP session over [input]/[protocolOut] until the peer closes the stream. Blocks.
 * The streams are parameters so tests can drive a full session through pipes.
 */
internal fun runStdio(
    client: Rapid7Client,
    config: Config,
    protocolOut: PrintStream,
    input: InputStream = System.`in`,
) = runBlocking {
    System.err.println("[insightvm-mcp] Starting over stdio - ${describeConfig(config)}")
    val built = buildInsightVmServer(client, config)
    logRegistration(built)
    val checkScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val updateCheck = checkScope.startUpdateCheck(config)
    val transport = StdioServerTransport(
        input = input.asSource().buffered(),
        output = protocolOut.asSink().buffered(),
    )

    // The transport fires onClose when stdin reaches EOF; register it before starting the session
    // so the process exits cleanly instead of blocking on done.join() forever.
    val done = Job()
    transport.onClose { done.complete() }
    try {
        val session = built.server.createSession(transport)
        checkScope.notifyWhenInitialized(built.server, session, updateCheck, config)
        done.join()
    } finally {
        updateCheck?.cancel()
        checkScope.cancel()
        client.close()
    }
}

/** Everything [runHttp] needs to start and later tear down; returned unstarted so tests can drive it. */
internal class HttpRuntime(
    val engine: EmbeddedServer<*, *>,
    private val checkScope: CoroutineScope,
    private val updateCheck: Deferred<UpdateChecker.Result>?,
    private val client: Rapid7Client,
) {
    fun shutdown() {
        updateCheck?.cancel()
        checkScope.cancel()
        client.close()
    }
}

/** Build the HTTP transport (security guard + MCP routes) without starting it. */
internal fun buildHttpRuntime(client: Rapid7Client, config: Config, host: String, port: Int): HttpRuntime {
    System.err.println("[insightvm-mcp] Starting over HTTP on $host:$port - ${describeConfig(config)}")
    if (config.httpAuthToken == null) {
        System.err.println(
            "[insightvm-mcp] WARNING: no ${Config.ENV_MCP_AUTH_TOKEN} set; any local process can call this server on $host:$port.",
        )
    }
    val catalogs = CatalogLoader.loadAll(config.activeFamilies)
    // Build once for logging; mcp { } builds a server per connection from the same catalogs.
    logRegistration(buildInsightVmServer(client, config, catalogs))

    val checkScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val updateCheck = checkScope.startUpdateCheck(config)
    val engine = embeddedServer(CIO, host = host, port = port) {
        installTransportSecurity(
            HttpSecurity(
                bindHost = host,
                bindPort = port,
                token = config.httpAuthToken,
                allowedOrigins = config.httpAllowedOrigins,
            ),
        )
        // One server per connection (both SDK transports build on demand); the update notifier is
        // attached to each so every session gets the notice exactly once.
        val newServer: () -> Server = {
            buildInsightVmServer(client, config, catalogs).server.also { server ->
                if (updateCheck != null) {
                    server.attachUpdateNotifier(checkScope) { session ->
                        val result = runCatching { updateCheck.await() }.getOrNull()
                        if (result != null) {
                            server.notifyUpdateAvailable(session, result)
                            if (result.updateAvailable) {
                                val outcome = autoInstall(config, result)
                                if (outcome != null) server.notifyUpdateInstalled(session, outcome)
                            }
                        }
                    }
                }
            }
        }
        // Host/Origin validation is done by installTransportSecurity (it also understands non-loopback
        // binds); the SDK's own DNS-rebinding guard is localhost-only, so it is switched off here.
        // Streamable HTTP (current spec) on /mcp — this also installs the SSE plugin ...
        mcpStreamableHttp(path = STREAMABLE_HTTP_PATH, enableDnsRebindingProtection = false) { newServer() }
        // ... which the legacy HTTP+SSE transport (GET /sse stream, POST /sse messages) relies on.
        routing { legacySseTransport(LEGACY_SSE_PATH, newServer = newServer) }
    }
    return HttpRuntime(engine, checkScope, updateCheck, client)
}

private fun runHttp(client: Rapid7Client, config: Config, host: String, port: Int) {
    val runtime = buildHttpRuntime(client, config, host, port)
    try {
        runtime.engine.start(wait = true)
    } finally {
        runtime.shutdown()
    }
}
