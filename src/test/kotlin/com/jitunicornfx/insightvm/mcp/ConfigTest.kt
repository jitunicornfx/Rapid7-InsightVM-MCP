package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ConfigTest {

    private val consoleEnv = mapOf(
        Config.ENV_CONSOLE_URL to "https://console.example.internal",
        Config.ENV_CONSOLE_USERNAME to "api",
        Config.ENV_CONSOLE_PASSWORD to "pw",
    )
    private val cloudEnv = mapOf(Config.ENV_API_KEY to "key", Config.ENV_REGION to "eu")

    @Test
    fun `console only`() {
        val c = Config.fromEnv(consoleEnv)
        assertNotNull(c.console)
        assertNull(c.cloud)
        assertEquals("https://console.example.internal:3780", c.console!!.baseUrl)
        assertEquals(setOf(ApiFamily.CONSOLE), c.activeFamilies)
    }

    @Test
    fun `cloud only with region and defaults`() {
        val c = Config.fromEnv(cloudEnv)
        assertNull(c.console)
        assertEquals(Region.EU, c.cloud!!.region)
        assertEquals("https://eu.api.insight.rapid7.com/vm", c.cloud!!.baseUrl)
        assertEquals(setOf(ApiFamily.CLOUD), c.activeFamilies)
        assertEquals(Config.DEFAULT_TIMEOUT_MS, c.requestTimeoutMillis)
        assertEquals(Config.DEFAULT_MAX_RESPONSE_BYTES, c.maxResponseBytes)
        assertFalse(c.updateCheckDisabled)
    }

    @Test
    fun `cloud defaults to us region and honours base url override`() {
        assertEquals(Region.US, Config.fromEnv(mapOf(Config.ENV_API_KEY to "k")).cloud!!.region)
        val c = Config.fromEnv(mapOf(Config.ENV_API_KEY to "k", Config.ENV_CLOUD_BASE_URL to "https://mock.local/vm/"))
        assertEquals("https://mock.local/vm", c.cloud!!.baseUrl)
    }

    @Test
    fun `both families`() {
        val c = Config.fromEnv(consoleEnv + cloudEnv)
        assertEquals(ApiFamily.entries.toSet(), c.activeFamilies)
    }

    @Test
    fun `neither family is an error`() {
        val e = assertFailsWith<IllegalArgumentException> { Config.fromEnv(emptyMap()) }
        assertTrue(e.message!!.contains(Config.ENV_CONSOLE_URL))
        assertTrue(e.message!!.contains(Config.ENV_API_KEY))
    }

    @Test
    fun `partial console configuration is an error, not a silent skip`() {
        val e = assertFailsWith<IllegalStateException> { Config.fromEnv(consoleEnv - Config.ENV_CONSOLE_PASSWORD) }
        assertTrue(e.message!!.contains("Incomplete"))
        assertFailsWith<IllegalStateException> { Config.fromEnv(mapOf(Config.ENV_CONSOLE_URL to "https://x")) }
    }

    @Test
    fun `region without api key and no console is an error`() {
        assertFailsWith<IllegalStateException> { Config.fromEnv(mapOf(Config.ENV_REGION to "us")) }
    }

    @Test
    fun `unknown region is rejected with the valid list`() {
        val e = assertFailsWith<IllegalArgumentException> { Config.fromEnv(mapOf(Config.ENV_API_KEY to "k", Config.ENV_REGION to "mars")) }
        assertTrue(e.message!!.contains("aps2"))
        assertTrue(e.message!!.contains("me1"))
        assertEquals(Region.APS2, Region.fromCode(" APS2 "))
    }

    @Test
    fun `console url normalisation`() {
        assertEquals("https://host:3780", Config.normalizeConsoleUrl("https://HOST"))
        assertEquals("https://host:3780", Config.normalizeConsoleUrl("https://host/"))
        assertEquals("https://host:8443", Config.normalizeConsoleUrl("https://host:8443"))
        assertEquals("https://host:443", Config.normalizeConsoleUrl("https://host:443"))
        assertEquals("http://host:3780", Config.normalizeConsoleUrl("http://host", allowHttp = true))
    }

    @Test
    fun `console url rejects cleartext, paths, credentials and junk`() {
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("http://host") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("https://host/api/3") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("https://user:pw@host") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("https://host?x=1") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("https://host#frag") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("ftp://host") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("not a url") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("https://") }
        assertFailsWith<IllegalArgumentException> { Config.normalizeConsoleUrl("https:///path") }
    }

    @Test
    fun `console env allows http only when explicitly enabled`() {
        val env = consoleEnv + (Config.ENV_CONSOLE_URL to "http://console.lab")
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(env) }
        val c = Config.fromEnv(env + (Config.ENV_ALLOW_HTTP to "true"))
        assertEquals("http://console.lab:3780", c.console!!.baseUrl)
    }

    @Test
    fun `cloud base url override must be https unless allowed`() {
        val env = mapOf(Config.ENV_API_KEY to "k", Config.ENV_CLOUD_BASE_URL to "http://mock.local/vm")
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(env) }
        assertEquals("http://mock.local/vm", Config.fromEnv(env + (Config.ENV_ALLOW_HTTP to "1")).cloud!!.baseUrl)
    }

    @Test
    fun `console optional settings`() {
        val c = Config.fromEnv(
            consoleEnv + mapOf(
                Config.ENV_CONSOLE_2FA_TOKEN to "123456",
                Config.ENV_CONSOLE_CA_CERT to "/certs/ca.pem",
                Config.ENV_CONSOLE_INSECURE_TLS to "yes",
            ),
        )
        assertEquals("123456", c.console!!.twoFactorToken)
        assertEquals("/certs/ca.pem", c.console!!.caCertPath)
        assertTrue(c.console!!.insecureTls)
    }

    @Test
    fun `numeric and list settings`() {
        val c = Config.fromEnv(
            cloudEnv + mapOf(
                Config.ENV_TIMEOUT_MS to "1500",
                Config.ENV_MAX_RESPONSE_BYTES to "1234",
                Config.ENV_HTTP_ALLOWED_ORIGINS to " https://a.example , * ,https://b.example,",
                Config.ENV_MCP_AUTH_TOKEN to "tok",
                Config.ENV_TAGS to "Site, Asset",
                Config.ENV_EXCLUDE_TAGS to "User",
                Config.ENV_READ_ONLY to "1",
                Config.ENV_ALLOW_ADMIN_COMMANDS to "on",
                Config.ENV_ALLOW_SECRET_TOOLS to "yes",
                Config.ENV_DISABLE_UPDATE_CHECK to "true",
                Config.ENV_DISABLE_AUTO_UPDATE to "1",
            ),
        )
        assertEquals(1500, c.requestTimeoutMillis)
        assertEquals(1234, c.maxResponseBytes)
        assertEquals(listOf("https://a.example", "https://b.example"), c.httpAllowedOrigins)
        assertEquals("tok", c.httpAuthToken)
        assertEquals(setOf("Site", "Asset"), c.filter.tags)
        assertEquals(setOf("User"), c.filter.excludeTags)
        assertTrue(c.filter.readOnly)
        assertTrue(c.filter.allowAdminCommands)
        assertTrue(c.filter.allowSecretTools)
        assertFalse(Config.fromEnv(cloudEnv).filter.allowSecretTools, "off unless set")
        assertTrue(c.updateCheckDisabled)
        assertTrue(c.autoUpdateDisabled)
    }

    @Test
    fun `the result budget has a floor, a ceiling and no unlimited value`() {
        fun chars(value: String?) =
            Config.fromEnv(cloudEnv + (if (value == null) emptyMap() else mapOf(Config.ENV_MAX_RESULT_CHARS to value))).maxResultChars
        assertEquals(Config.DEFAULT_MAX_RESULT_CHARS, chars(null))
        assertEquals(Config.DEFAULT_MAX_RESULT_CHARS, chars("abc"))
        assertEquals(Config.DEFAULT_MAX_RESULT_CHARS, chars("0"))
        assertEquals(Config.DEFAULT_MAX_RESULT_CHARS, chars("-5"))
        assertEquals(Config.MIN_MAX_RESULT_CHARS, chars("1"), "a tiny value clamps up to something diagnostic")
        assertEquals(Config.MAX_MAX_RESULT_CHARS, chars("99999999"), "there is no unlimited value")
        assertEquals(50_000, chars("50000"))
    }

    @Test
    fun `the wire byte cap is clamped so an env typo cannot exhaust the heap`() {
        fun bytes(value: String) = Config.fromEnv(cloudEnv + (Config.ENV_MAX_RESPONSE_BYTES to value)).maxResponseBytes
        assertEquals(Config.MAX_RESPONSE_BYTES_CEILING, bytes("99999999999"))
        assertEquals(1234, bytes("1234"))
        assertTrue(
            Config.DEFAULT_MAX_RESPONSE_BYTES > Config.DEFAULT_MAX_RESULT_CHARS.toLong(),
            "the wire guard must exceed the render budget, or trimming never sees a complete document",
        )
    }

    @Test
    fun `invalid numeric settings fall back to defaults`() {
        val c = Config.fromEnv(cloudEnv + mapOf(Config.ENV_TIMEOUT_MS to "-5", Config.ENV_MAX_RESPONSE_BYTES to "abc"))
        assertEquals(Config.DEFAULT_TIMEOUT_MS, c.requestTimeoutMillis)
        assertEquals(Config.DEFAULT_MAX_RESPONSE_BYTES, c.maxResponseBytes)
    }

    @Test
    fun `flag parsing`() {
        listOf("1", "true", "YES", " on ").forEach { assertTrue(Config.parseFlag("F", it), it) }
        listOf("0", "false", "No", " OFF ", "", "  ", null).forEach { assertFalse(Config.parseFlag("F", it), it ?: "null") }
        listOf("maybe", "y", "2", "enabled", "read-only").forEach { value ->
            val e = assertFailsWith<IllegalArgumentException>(value) { Config.parseFlag("SOME_FLAG", value) }
            assertEquals("SOME_FLAG must be one of 1/true/yes/on or 0/false/no/off.", e.message)
        }
        assertEquals(emptyList(), Config.csv(null))
        assertEquals(listOf("a", "b"), Config.csv(" a ,, b "))
    }

    @Test
    fun `an unrecognised flag value fails startup instead of leaving a safety flag off`() {
        // Every boolean variable, so none can quietly fall back to "off" on a typo.
        val flags = listOf(
            Config.ENV_READ_ONLY, Config.ENV_DISABLE_EXPORT, Config.ENV_DISABLE_UPDATE_CHECK, Config.ENV_DISABLE_AUTO_UPDATE,
            Config.ENV_ALLOW_ADMIN_COMMANDS, Config.ENV_ALLOW_HTTP, Config.ENV_CONSOLE_INSECURE_TLS, Config.ENV_KEEP_RECORD_LINKS,
            Config.ENV_ALLOW_SECRET_TOOLS,
        )
        for (flag in flags) {
            val e = assertFailsWith<IllegalArgumentException>(flag) { Config.fromEnv(consoleEnv + cloudEnv + (flag to "y")) }
            assertContains(e.message!!, flag)
            assertContains(e.message!!, "1/true/yes/on or 0/false/no/off")
        }
        // A console flag is checked even when the console is not configured: a typo is a typo.
        assertFailsWith<IllegalArgumentException> { Config.fromEnv(cloudEnv + (Config.ENV_CONSOLE_INSECURE_TLS to "enabled")) }

        assertFalse(Config.fromEnv(cloudEnv + (Config.ENV_READ_ONLY to "off")).filter.readOnly)
        assertTrue(Config.fromEnv(cloudEnv + (Config.ENV_READ_ONLY to "ON")).filter.readOnly)
        assertFalse(Config.fromEnv(cloudEnv + (Config.ENV_READ_ONLY to " ")).filter.readOnly, "blank is unset")
    }

    @Test
    fun `secret values are trimmed, and one that cannot be a header value fails startup without being echoed`() {
        // A secret with a character no HTTP header may carry: named by variable and position, never shown.
        val badKey = assertFailsWith<IllegalArgumentException> { Config.fromEnv(mapOf(Config.ENV_API_KEY to "s3cr\u0007etKEY")) }
        assertContains(badKey.message!!, Config.ENV_API_KEY)
        assertContains(badKey.message!!, "position 5")
        assertFalse(badKey.message!!.contains("s3cr"), badKey.message)
        assertFalse(badKey.message!!.contains("etKEY"), badKey.message)

        // A non-breaking space inside the value (a paste from a web page); positions count from the raw value.
        val nbsp = assertFailsWith<IllegalArgumentException> { Config.fromEnv(mapOf(Config.ENV_API_KEY to "  key part")) }
        assertContains(nbsp.message!!, "position 6")
        assertFalse(nbsp.message!!.contains("part"), nbsp.message)

        val bad2fa = assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(consoleEnv + (Config.ENV_CONSOLE_2FA_TOKEN to "123\r456"))
        }
        assertContains(bad2fa.message!!, Config.ENV_CONSOLE_2FA_TOKEN)
        assertFalse(bad2fa.message!!.contains("123"), bad2fa.message)

        val badBearer = assertFailsWith<IllegalArgumentException> {
            Config.fromEnv(cloudEnv + (Config.ENV_MCP_AUTH_TOKEN to "two words"))
        }
        assertContains(badBearer.message!!, Config.ENV_MCP_AUTH_TOKEN)
        assertFalse(badBearer.message!!.contains("words"), badBearer.message)

        // Surrounding whitespace is trimmed: pasted padding, and the CR a CRLF env file leaves behind.
        assertEquals("key", Config.fromEnv(mapOf(Config.ENV_API_KEY to "  key  ")).cloud!!.apiKey)
        assertEquals("abc", Config.fromEnv(mapOf(Config.ENV_API_KEY to "abc\r")).cloud!!.apiKey)
        assertEquals("123456", Config.fromEnv(consoleEnv + (Config.ENV_CONSOLE_2FA_TOKEN to " 123456\n")).console!!.twoFactorToken)
        // Presented tokens are trimmed by the Authorization parser, so a padded stored one could never match.
        assertEquals("s3cret", Config.fromEnv(cloudEnv + (Config.ENV_MCP_AUTH_TOKEN to "s3cret ")).httpAuthToken)
    }

    @Test
    fun `secrets never appear in toString`() {
        val c = Config.fromEnv(
            consoleEnv + cloudEnv + mapOf(Config.ENV_CONSOLE_2FA_TOKEN to "otp-secret", Config.ENV_MCP_AUTH_TOKEN to "bearer-secret"),
        )
        val s = c.toString()
        assertFalse(s.contains("pw"), s)
        assertFalse(s.contains("key)"), s)
        assertFalse(s.contains("otp-secret"), s)
        assertFalse(s.contains("bearer-secret"), s)
        assertTrue(s.contains("password=***"))
        assertTrue(s.contains("apiKey=***"))
        assertTrue(c.console.toString().contains("twoFactorToken=***"))
        assertTrue(ConsoleConfig("https://h:1", "u", "p").toString().contains("twoFactorToken=unset"))
        assertTrue(Config(console = null, cloud = c.cloud).toString().contains("httpAuthToken=unset"))
    }

    @Test
    fun `activeFamilies respects the filter`() {
        val c = Config.fromEnv(consoleEnv + cloudEnv).let { it.copy(filter = it.filter.copy(families = setOf(ApiFamily.CLOUD))) }
        assertEquals(setOf(ApiFamily.CLOUD), c.activeFamilies)
    }

    @Test
    fun `ToolFilter tighten is monotonic`() {
        val env = ToolFilter(readOnly = false, tags = setOf("Site", "Asset"), excludeTags = setOf("User"), allowAdminCommands = true, allowSecretTools = true)
        val cli = ToolFilter(readOnly = true, tags = setOf("asset", "Scan"), excludeTags = setOf("Tag"), allowAdminCommands = false, families = setOf(ApiFamily.CONSOLE), nameGlobs = listOf("get_*"))
        val t = env.tighten(cli)
        assertTrue(t.readOnly)
        assertEquals(setOf("asset"), t.tags)
        assertEquals(setOf("User", "Tag"), t.excludeTags)
        assertFalse(t.allowAdminCommands)
        assertFalse(t.allowSecretTools)
        assertTrue(env.tighten(env).allowSecretTools, "both must allow it")
        assertEquals(setOf(ApiFamily.CONSOLE), t.families)
        assertEquals(listOf("get_*"), t.nameGlobs)

        // Disjoint tag sets select nothing rather than falling back to everything.
        val disjoint = ToolFilter(tags = setOf("Site")).tighten(ToolFilter(tags = setOf("User")))
        assertEquals(setOf(ToolFilter.NO_TAGS_SENTINEL), disjoint.tags)
        assertEquals(setOf("Site"), ToolFilter(tags = setOf("Site")).tighten(ToolFilter()).tags)
        assertEquals(setOf("Site"), ToolFilter().tighten(ToolFilter(tags = setOf("Site"))).tags)
    }

    @Test
    fun `ApiFamily parsing`() {
        assertEquals(ApiFamily.CLOUD, ApiFamily.fromId(" Cloud "))
        assertFailsWith<IllegalArgumentException> { ApiFamily.fromId("saas") }
    }
}
