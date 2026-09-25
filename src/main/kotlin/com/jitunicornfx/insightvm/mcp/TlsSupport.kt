package com.jitunicornfx.insightvm.mcp

import okhttp3.OkHttpClient
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * TLS trust configuration for the on-premises Security Console, which typically presents a
 * self-signed or private-CA certificate.
 *
 *  - Default: the JVM's trust store; hostname verification on.
 *  - [ConsoleConfig.caCertPath]: trust exactly the certificate(s) in that PEM file (a private CA or
 *    the console's own self-signed leaf); hostname verification stays on. The one exception: when the
 *    file holds a single self-signed certificate, a server presenting exactly that certificate is
 *    accepted under any host name ([pinnedLeafVerifier]).
 *  - [ConsoleConfig.insecureTls]: trust anything and skip hostname verification. Only for lab use;
 *    announced loudly on stderr.
 */
object TlsSupport {

    const val INSECURE_BANNER =
        "[insightvm-mcp] WARNING: TLS certificate and hostname verification for the Security Console is DISABLED " +
            "(${Config.ENV_CONSOLE_INSECURE_TLS}). Credentials can be intercepted by anyone on the network path. " +
            "Prefer ${Config.ENV_CONSOLE_CA_CERT} with the console's CA certificate, or with its own self-signed " +
            "certificate, which is then accepted at any host name or IP address."

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

    /**
     * The certificate to pin as the console's leaf: [trustManager]'s only anchor, when that anchor is
     * self-signed. A trust manager from [trustManagerFromPemStream] has exactly the PEM's distinct
     * certificates as its anchors, so this is "the file holds one self-signed certificate". A bundle,
     * or a single certificate that some CA issued, returns null and keeps OkHttp's strict check.
     */
    private fun soleSelfSignedAnchor(trustManager: X509TrustManager): X509Certificate? =
        trustManager.acceptedIssuers.singleOrNull()?.takeIf(::isSelfSigned)

    /** Its subject is its issuer, and its own key verifies its signature: a name match alone is not enough. */
    private fun isSelfSigned(cert: X509Certificate): Boolean =
        cert.subjectX500Principal == cert.issuerX500Principal &&
            try {
                cert.verify(cert.publicKey)
                true
            } catch (_: GeneralSecurityException) {
                false
            }

    /**
     * [strict], widened for a console pinned by its own self-signed certificate: a server whose leaf
     * certificate is exactly [pinned] is accepted under any host name.
     *
     * A console reached by IP address, or by a name its certificate does not list, fails OkHttp's check
     * even with its exact certificate trusted, and the only option left was
     * [ConsoleConfig.insecureTls], which trusts any certificate from anyone. Accepting the pinned leaf is
     * at least as strong as a host name check: [pinned] is the trust manager's only anchor, so by the
     * time this runs the handshake has proved the server holds its private key, and the operator named
     * that certificate byte for byte. A leaf that [pinned] merely issued (a private CA) still has to name
     * the host, because only the certificate itself, as the leaf, is accepted.
     */
    private fun pinnedLeafVerifier(strict: HostnameVerifier, pinned: X509Certificate): HostnameVerifier =
        HostnameVerifier { host, session -> strict.verify(host, session) || presentsLeaf(session, pinned) }

    private fun presentsLeaf(session: SSLSession, pinned: X509Certificate): Boolean =
        try {
            session.peerCertificates.firstOrNull() == pinned
        } catch (_: SSLPeerUnverifiedException) {
            false
        }

    /** Apply [console]'s trust settings to an OkHttp client builder. */
    fun apply(builder: OkHttpClient.Builder, console: ConsoleConfig, warn: (String) -> Unit = { System.err.println(it) }) {
        val tm = trustManagerFor(console) ?: return
        builder.sslSocketFactory(sslContextFor(tm).socketFactory, tm)
        if (console.insecureTls) {
            builder.hostnameVerifier(insecureHostnameVerifier)
            warn(INSECURE_BANNER)
            return
        }
        val pinned = soleSelfSignedAnchor(tm) ?: return
        // OkHttp exposes a builder's verifier only on a client built from it (its default unless the
        // caller set one); building one makes no connection.
        builder.hostnameVerifier(pinnedLeafVerifier(builder.build().hostnameVerifier, pinned))
    }
}
