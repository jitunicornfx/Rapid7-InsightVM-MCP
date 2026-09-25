package com.jitunicornfx.insightvm.mcp.catalog

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** The two InsightVM API families this server can front. */
enum class ApiFamily(val id: String, val toolPrefix: String, val resource: String, val displayName: String) {
    CONSOLE("console", "", "/catalog/v3.json", "Security Console API v3"),
    CLOUD("cloud", "cloud_", "/catalog/v4.json", "Cloud Integrations API v4");

    companion object {
        fun fromId(value: String): ApiFamily =
            entries.firstOrNull { it.id == value.trim().lowercase() }
                ?: throw IllegalArgumentException("Unknown API family '$value'. Valid values: ${entries.joinToString { it.id }}")
    }
}

@Serializable
data class CatalogParam(
    val name: String,
    val `in`: String,
    val required: Boolean = false,
    val array: Boolean = false,
    val schema: JsonObject,
) {
    val isPath: Boolean get() = `in` == "path"
    val isQuery: Boolean get() = `in` == "query"
}

@Serializable
data class CatalogBody(
    val contentType: String,
    val required: Boolean = false,
    val schema: JsonObject,
) {
    val isJson: Boolean get() = contentType == "application/json"
}

@Serializable
data class CatalogResponses(
    val success: String = "application/json",
    val binary: Boolean = false,
)

@Serializable
data class CatalogOp(
    val name: String,
    val opId: String,
    val method: String,
    val path: String,
    val tag: String = "Untagged",
    val summary: String = "",
    val description: String = "",
    val readOnly: Boolean,
    val destructive: Boolean = false,
    val admin: Boolean = false,
    /**
     * Returns or sets an authentication secret (a user's 2FA seed or password, the engine pairing
     * secret), so it is registered only with `--allow-secret-tools`. See [CatalogLoader.SENSITIVE_OPS].
     */
    val sensitive: Boolean = false,
    val params: List<CatalogParam> = emptyList(),
    val body: CatalogBody? = null,
    val responses: CatalogResponses = CatalogResponses(),
)

@Serializable
data class CatalogMeta(
    val family: String,
    val title: String = "",
    val specVersion: String = "",
    val specSha256: String = "",
    val generator: String = "",
    val generatedFrom: String = "",
    val opCount: Int,
)

@Serializable
data class Catalog(
    val meta: CatalogMeta,
    val ops: List<CatalogOp>,
)
