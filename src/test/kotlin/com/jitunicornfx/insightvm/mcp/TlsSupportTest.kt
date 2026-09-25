package com.jitunicornfx.insightvm.mcp

import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.ByteArrayInputStream
import java.io.IOException
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSession
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TlsSupportTest {

    private val pemPath: String = java.nio.file.Paths.get(javaClass.getResource("/tls/test-ca.pem")!!.toURI()).toString()
    private val pemBytes: ByteArray = javaClass.getResource("/tls/test-ca.pem")!!.readBytes()
    private val testCert: X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(pemBytes)) as X509Certificate

    /** A certificate that is not [testCert]: the first root in the JDK's own trust store. */
    private val someRoot: X509Certificate =
        javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as KeyStore?) }.trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>().first()
            .acceptedIssuers.first()

    /** The verifier OkHttp uses when nothing replaces it. */
    private val defaultVerifier: HostnameVerifier = OkHttpClient.Builder().build().hostnameVerifier

    @Test
    fun `trust manager from pem trusts exactly the bundled certificate`() {
        val tm = TlsSupport.trustManagerFromPem(pemPath)
        assertEquals(listOf(testCert), tm.acceptedIssuers.toList())
        tm.checkServerTrusted(arrayOf(testCert), "RSA")
        // A different self-signed certificate is not trusted.
        val other = TlsSupport.trustManagerFromPemStream(ByteArrayInputStream(pemBytes)).acceptedIssuers.single()
        assertEquals(testCert, other)
        assertFailsWith<CertificateException> { tm.checkServerTrusted(arrayOf(someRoot), "RSA") }
    }

    @Test
    fun `bad pem inputs produce clear errors`() {
        val missing = assertFailsWith<IllegalArgumentException> { TlsSupport.trustManagerFromPem("/definitely/not/here.pem") }
        assertTrue(missing.message!!.contains(Config.ENV_CONSOLE_CA_CERT))
        val garbage = java.nio.file.Paths.get(javaClass.getResource("/tls/not-a-cert.pem")!!.toURI()).toString()
        val e = assertFailsWith<IllegalArgumentException> { TlsSupport.trustManagerFromPem(garbage) }
        assertTrue(e.message!!.contains("contains no certificates") || e.message!!.contains("valid PEM"), e.message)
        val empty = Files.createTempFile("empty", ".pem")
        try {
            assertFailsWith<IllegalArgumentException> { TlsSupport.trustManagerFromPem(empty.toString()) }
        } finally {
            Files.deleteIfExists(empty)
        }
    }

    @Test
    fun `insecure trust manager and verifier accept anything`() {
        TlsSupport.insecureTrustManager.checkServerTrusted(null, null)
        TlsSupport.insecureTrustManager.checkClientTrusted(null, null)
        assertEquals(0, TlsSupport.insecureTrustManager.acceptedIssuers.size)
        assertTrue(TlsSupport.insecureHostnameVerifier.verify("anything", null))
        assertNotNull(TlsSupport.sslContextFor(TlsSupport.insecureTrustManager).socketFactory)
    }

    @Test
    fun `trustManagerFor picks by configuration`() {
        val base = ConsoleConfig("https://c:3780", "u", "p")
        assertNull(TlsSupport.trustManagerFor(base))
        assertEquals(TlsSupport.insecureTrustManager, TlsSupport.trustManagerFor(base.copy(insecureTls = true, caCertPath = pemPath)))
        assertEquals(listOf(testCert), TlsSupport.trustManagerFor(base.copy(caCertPath = pemPath))!!.acceptedIssuers.toList())
    }

    @Test
    fun `apply configures the OkHttp builder and warns only when insecure`() {
        val base = ConsoleConfig("https://c:3780", "u", "p")
        val warnings = mutableListOf<String>()

        val untouched = OkHttpClient.Builder()
        TlsSupport.apply(untouched, base, warnings::add)
        assertTrue(warnings.isEmpty())
        assertEquals(defaultVerifier, untouched.build().hostnameVerifier)

        // test-ca.pem is one self-signed certificate, so it is pinned: see the tests below.
        val withCa = OkHttpClient.Builder()
        TlsSupport.apply(withCa, base.copy(caCertPath = pemPath), warnings::add)
        val caClient = withCa.build()
        assertEquals(listOf(testCert), caClient.x509TrustManager!!.acceptedIssuers.toList())
        assertNotEquals(defaultVerifier, caClient.hostnameVerifier)
        assertNotEquals(TlsSupport.insecureHostnameVerifier, caClient.hostnameVerifier)
        assertTrue(warnings.isEmpty())

        val insecure = OkHttpClient.Builder()
        TlsSupport.apply(insecure, base.copy(insecureTls = true), warnings::add)
        val insecureClient = insecure.build()
        assertNotEquals(defaultVerifier, insecureClient.hostnameVerifier)
        assertEquals(TlsSupport.insecureHostnameVerifier, insecureClient.hostnameVerifier)
        assertEquals(listOf(TlsSupport.INSECURE_BANNER), warnings)
    }

    @Test
    fun `a pinned self-signed certificate is accepted for a host it does not name`() {
        val verifier = verifierFor(pemPath)
        // test-ca.pem names no host at all, so OkHttp's own check refuses every one of them.
        assertFalse(defaultVerifier.verify("10.0.0.5", sessionPresenting(testCert)))
        assertTrue(verifier.verify("10.0.0.5", sessionPresenting(testCert)))
        assertTrue(verifier.verify("console.corp.example", sessionPresenting(testCert)))
    }

    @Test
    fun `the pinned verifier accepts nothing but the pinned certificate as the leaf`() {
        val verifier = verifierFor(pemPath)
        assertFalse(verifier.verify("10.0.0.5", sessionPresenting(someRoot)))
        // The pinned certificate further up the chain is a CA that issued the leaf, not the leaf itself.
        assertFalse(verifier.verify("10.0.0.5", sessionPresenting(someRoot, testCert)))
        assertFalse(verifier.verify("10.0.0.5", sessionPresenting()))
    }

    @Test
    fun `a bundle or a certificate that is not self-signed keeps the strict hostname check`() {
        val dir = Files.createTempDirectory("tls-pin")
        try {
            val twoCerts = dir.resolve("two.pem").apply { writeText(pemOf(testCert, someRoot)) }
            assertEquals(defaultVerifier, verifierFor(twoCerts.toString()))
            assertFalse(verifierFor(twoCerts.toString()).verify("10.0.0.5", sessionPresenting(testCert)))

            // Same subject and issuer, but the signature no longer verifies with its own key.
            val encoded = testCert.encoded.also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
            val forged = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
            assertEquals(forged.subjectX500Principal, forged.issuerX500Principal)
            val forgedPem = dir.resolve("forged.pem").apply { writeText(pemOf(forged)) }
            assertEquals(defaultVerifier, verifierFor(forgedPem.toString()))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `a console reached by IP address connects when its self-signed certificate is pinned`() {
        withKeys(listOf("self")) { keys, dir ->
            val selfPem = dir.resolve("self.pem").apply { writeText(pemOf(keys.getCertificate("self"))) }
            LoopbackTlsServer(keys, "self").use { server ->
                // The certificate names console.invalid only; before pinning, OkHttp refused 127.0.0.1.
                assertEquals(200, get(selfPem, "127.0.0.1", server.port))
                assertEquals(200, get(selfPem, "console.invalid", server.port))
                // A different self-signed certificate is refused by the trust manager, before any host check.
                assertFailsWith<SSLHandshakeException> { get(Path.of(pemPath), "127.0.0.1", server.port) }
            }
        }
    }

    @Test
    fun `a CA or a CA-issued leaf pinned alone still has to name the host`() {
        withKeys(listOf("ca", "leaf:ca")) { keys, dir ->
            val caPem = dir.resolve("ca.pem").apply { writeText(pemOf(keys.getCertificate("ca"))) }
            val leafPem = dir.resolve("leaf.pem").apply { writeText(pemOf(keys.getCertificate("leaf"))) }
            LoopbackTlsServer(keys, "leaf").use { server ->
                // The host the leaf names passes, so what fails below is the host name and nothing else.
                assertEquals(200, get(caPem, "console.invalid", server.port))
                val e = assertFailsWith<SSLPeerUnverifiedException> { get(caPem, "127.0.0.1", server.port) }
                assertTrue(e.message!!.contains("not verified"), e.message)
                // The leaf alone is a trust anchor, but not a self-signed one, so it is not pinned either.
                assertEquals(200, get(leafPem, "console.invalid", server.port))
                assertFailsWith<SSLPeerUnverifiedException> { get(leafPem, "127.0.0.1", server.port) }
            }
        }
    }

    /** The hostname verifier [TlsSupport.apply] installs for a console trusting the PEM at [pem]. */
    private fun verifierFor(pem: String): HostnameVerifier =
        OkHttpClient.Builder().also { TlsSupport.apply(it, ConsoleConfig("https://c:3780", "u", "p", caCertPath = pem)) }
            .build().hostnameVerifier

    /** An [SSLSession] whose peer presented [chain], leaf first; an empty chain means the peer was not verified. */
    private fun sessionPresenting(vararg chain: X509Certificate): SSLSession =
        Proxy.newProxyInstance(javaClass.classLoader, arrayOf(SSLSession::class.java)) { _, method, _ ->
            when (method.name) {
                "getPeerCertificates" ->
                    if (chain.isEmpty()) throw SSLPeerUnverifiedException("peer not authenticated") else arrayOf<Certificate>(*chain)
                else -> throw UnsupportedOperationException(method.name)
            }
        } as SSLSession

    private fun pemOf(vararg certs: Certificate): String = certs.joinToString("") {
        "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(it.encoded) +
            "\n-----END CERTIFICATE-----\n"
    }

    /** GET https://[host]:[port]/ through a client that [TlsSupport.apply] set up to trust [pem]; every name resolves to loopback. */
    private fun get(pem: Path, host: String, port: Int): Int {
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .dns { listOf(LOOPBACK) }
        TlsSupport.apply(builder, ConsoleConfig("https://$host:$port", "u", "p", caCertPath = pem.toString()))
        val client = builder.build()
        try {
            return client.newCall(Request.Builder().url("https://$host:$port/").build()).execute().use { it.code }
        } finally {
            client.connectionPool.evictAll()
        }
    }

    /**
     * Throw-away EC keys made by the JDK's keytool for [aliases] ("name", or "name:signer" for one issued by an
     * earlier alias), so no private key lives in the repository. A CA alias ("ca") gets the CA basic constraint;
     * every other one names console.invalid. Skipped where the runtime has no keytool.
     */
    private fun withKeys(aliases: List<String>, block: (KeyStore, Path) -> Unit) {
        val keytool = Path.of(System.getProperty("java.home"), "bin", if (isWindows) "keytool.exe" else "keytool")
        assumeTrue(Files.isRegularFile(keytool), "no keytool in this Java runtime")
        val dir = Files.createTempDirectory("tls-keys")
        try {
            val store = dir.resolve("keys.p12")
            for (spec in aliases) {
                val alias = spec.substringBefore(':')
                val signer = spec.substringAfter(':', "")
                val args = mutableListOf(
                    keytool.toString(), "-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1",
                    "-validity", "2", "-keystore", store.toString(), "-storetype", "PKCS12",
                    "-storepass", STORE_PASSWORD, "-keypass", STORE_PASSWORD, "-noprompt",
                )
                if (alias == "ca") args += listOf("-dname", "CN=insightvm-mcp test console CA", "-ext", "bc:c")
                else args += listOf("-dname", "CN=console.invalid", "-ext", "san=dns:console.invalid")
                if (signer.isNotEmpty()) args += listOf("-signer", signer, "-signerkeypass", STORE_PASSWORD)
                val process = ProcessBuilder(args).redirectErrorStream(true).start()
                val output = process.inputStream.bufferedReader().readText()
                assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool timed out")
                assertEquals(0, process.exitValue(), output)
            }
            val keys = KeyStore.getInstance("PKCS12").apply {
                Files.newInputStream(store).use { load(it, STORE_PASSWORD.toCharArray()) }
            }
            block(keys, dir)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    /**
     * A one-thread HTTPS server on 127.0.0.1 presenting [alias]'s key and chain from [keys]; it answers every request
     * `200 ok`. A client that refuses the certificate or the host name just ends the connection.
     */
    private class LoopbackTlsServer(keys: KeyStore, alias: String) : AutoCloseable {
        private val socket: SSLServerSocket
        private val thread: Thread
        val port: Int get() = socket.localPort

        init {
            val password = STORE_PASSWORD.toCharArray()
            val only = KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry(alias, keys.getKey(alias, password), password, keys.getCertificateChain(alias))
            }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(only, password) }
            val context = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
            socket = context.serverSocketFactory.createServerSocket(0, 8, LOOPBACK) as SSLServerSocket
            thread = Thread(::serve, "tls-test-server").apply { isDaemon = true; start() }
        }

        private fun serve() {
            while (true) {
                val connection = try {
                    socket.accept()
                } catch (_: IOException) {
                    return
                }
                try {
                    connection.use {
                        it.soTimeout = 10_000
                        val reader = it.getInputStream().bufferedReader(Charsets.ISO_8859_1)
                        do {
                            val header = reader.readLine() // skip the request line and headers
                        } while (!header.isNullOrEmpty())
                        it.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toByteArray())
                        it.getOutputStream().flush()
                    }
                } catch (_: IOException) {
                    // The client refused the certificate or the host name and closed the connection.
                }
            }
        }

        override fun close() {
            socket.close()
            thread.join(5_000)
        }
    }

    private companion object {
        const val STORE_PASSWORD = "changeit"
        val LOOPBACK: InetAddress = InetAddress.getByName("127.0.0.1")
        val isWindows = System.getProperty("os.name").startsWith("Windows")
    }
}
