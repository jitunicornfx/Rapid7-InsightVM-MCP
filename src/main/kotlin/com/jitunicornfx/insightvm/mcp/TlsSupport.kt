package com.jitunicornfx.insightvm.mcp

import okhttp3.OkHttpClient
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * TLS trust configuration for the on-premises Security Console, which typically presents a
 * self-signed or private-CA certificate.
 *
 *  - Default: the JVM's trust store; hostname verification on.
 *  - [ConsoleConfig.caCertPath]: trust exactly the certificate(s) in that PEM file (a private CA or
 *    the console's own self-signed leaf); hostname verification stays on.
 *  - [ConsoleConfig.insecureTls]: trust anything and skip hostname verification. Only for lab use;
 *    announced loudly on stderr.
 */
object TlsSupport {

    const val INSECURE_BANNER =
        "[insightvm-mcp] WARNING: TLS certificate and hostname verification for the Security Console is DISABLED " +
            "(${Config.ENV_CONSOLE_INSECURE_TLS}). Credentials can be intercepted by anyone on the network path. " +
            "Prefer ${Config.ENV_CONSOLE_CA_CERT} with the console's CA certificate."

    /** Build a trust manager that trusts only the X.509 certificates found in the PEM file at [pemPath]. */
    fun trustManagerFromPem(pemPath: String): X509TrustManager {
        val path = Path.of(pemPath)
        require(Files.isRegularFile(path)) { "${Config.ENV_CONSOLE_CA_CERT} does not point to a readable file: $pemPath" }
        Files.newInputStream(path).use { input -> return trustManagerFromPemStream(input, pemPath) }
    }

    internal fun trustManagerFromPemStream(input: InputStream, label: String = "<stream>"): X509TrustManager {
        val certs = try {
            CertificateFactory.getInstance("X.509").generateCertificates(input).filterIsInstance<X509Certificate>()
        } catch (e: Exception) {
            throw IllegalArgumentException("${Config.ENV_CONSOLE_CA_CERT} ($label) does not contain valid PEM/DER X.509 certificates: ${e.message}", e)
        }
        require(certs.isNotEmpty()) { "${Config.ENV_CONSOLE_CA_CERT} ($label) contains no certificates." }
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
        certs.forEachIndexed { i, cert -> keyStore.setCertificateEntry("insightvm-ca-$i", cert) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keyStore) }
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    /** A trust manager that accepts every certificate. Reachable only through [ConsoleConfig.insecureTls]. */
    internal val insecureTrustManager: X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    internal val insecureHostnameVerifier: HostnameVerifier = HostnameVerifier { _, _ -> true }

    fun sslContextFor(trustManager: X509TrustManager): SSLContext =
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), SecureRandom()) }

    /** Pick the trust manager for [console], or null when the JVM default trust store should be used. */
    internal fun trustManagerFor(console: ConsoleConfig): X509TrustManager? = when {
        console.insecureTls -> insecureTrustManager
        console.caCertPath != null -> trustManagerFromPem(console.caCertPath)
        else -> null
    }

    /** Apply [console]'s trust settings to an OkHttp client builder. */
    fun apply(builder: OkHttpClient.Builder, console: ConsoleConfig, warn: (String) -> Unit = { System.err.println(it) }) {
        val tm = trustManagerFor(console) ?: return
        builder.sslSocketFactory(sslContextFor(tm).socketFactory, tm)
        if (console.insecureTls) {
            builder.hostnameVerifier(insecureHostnameVerifier)
            warn(INSECURE_BANNER)
        }
    }
}
