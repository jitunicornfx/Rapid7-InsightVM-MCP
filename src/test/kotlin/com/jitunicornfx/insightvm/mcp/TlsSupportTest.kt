package com.jitunicornfx.insightvm.mcp

import okhttp3.OkHttpClient
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TlsSupportTest {

    private val pemPath: String = java.nio.file.Paths.get(javaClass.getResource("/tls/test-ca.pem")!!.toURI()).toString()
    private val pemBytes: ByteArray = javaClass.getResource("/tls/test-ca.pem")!!.readBytes()
    private val testCert: X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(pemBytes)) as X509Certificate

    @Test
    fun `trust manager from pem trusts exactly the bundled certificate`() {
        val tm = TlsSupport.trustManagerFromPem(pemPath)
        assertEquals(listOf(testCert), tm.acceptedIssuers.toList())
        tm.checkServerTrusted(arrayOf(testCert), "RSA")
        // A different self-signed certificate is not trusted.
        val other = TlsSupport.trustManagerFromPemStream(ByteArrayInputStream(pemBytes)).acceptedIssuers.single()
        assertEquals(testCert, other)
        val jdkDefault = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as java.security.KeyStore?) }.trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>().first()
        val someRoot = jdkDefault.acceptedIssuers.first()
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
        val defaultVerifier: HostnameVerifier = untouched.build().hostnameVerifier
        TlsSupport.apply(untouched, base, warnings::add)
        assertTrue(warnings.isEmpty())
        assertEquals(defaultVerifier, untouched.build().hostnameVerifier)

        val withCa = OkHttpClient.Builder()
        TlsSupport.apply(withCa, base.copy(caCertPath = pemPath), warnings::add)
        val caClient = withCa.build()
        assertEquals(listOf(testCert), caClient.x509TrustManager!!.acceptedIssuers.toList())
        assertEquals(defaultVerifier, caClient.hostnameVerifier)
        assertTrue(warnings.isEmpty())

        val insecure = OkHttpClient.Builder()
        TlsSupport.apply(insecure, base.copy(insecureTls = true), warnings::add)
        val insecureClient = insecure.build()
        assertNotEquals(defaultVerifier, insecureClient.hostnameVerifier)
        assertEquals(TlsSupport.insecureHostnameVerifier, insecureClient.hostnameVerifier)
        assertEquals(listOf(TlsSupport.INSECURE_BANNER), warnings)
    }
}
