package com.jitunicornfx.insightvm.mcp.catalog

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/** Turns a [CatalogOp] into the MCP tool description and JSON-Schema input. */
object InputSchemaBuilder {

    const val CONFIRM_VALUE = "EXECUTE"

    /**
     * The short form of the result-size policy, appended to paged tools only. A tool description is
     * paid on every session, so this stays terse; the long form lives in the truncation notice,
     * which is only paid when the model has already made the expensive choice.
     */
    const val PAGING_GUIDANCE =
        " Paged: 'size' defaults to ${PagingDefaults.DEFAULT_PAGE_SIZE} and is clamped to " +
            "${PagingDefaults.MAX_PAGE_SIZE}. For a COUNT ONLY, call with size=1 and read " +
            "page.totalResources (v3) or metadata.totalResources (v4) — a few hundred tokens instead of " +
            "enumerating. To read EVERY record use insightvm_export_to_file, which pages on the server " +
            "and returns only a summary. Per-record 'links' are stripped to save context."

    /** Tool description: summary, cleaned spec description, the HTTP route and any safety markers. */
    fun describe(op: CatalogOp, family: ApiFamily): String = buildString {
        if (op.summary.isNotBlank()) append(op.summary)
        if (op.description.isNotBlank()) {
            if (isNotEmpty()) append(" — ")
            append(op.description)
        }
        if (isNotEmpty()) append(' ')
        append("[${family.displayName}: ${op.method} ${op.path}]")
        if (op.admin) append(" [ADMIN: executes an arbitrary console command; requires confirm=\"$CONFIRM_VALUE\"]")
        else if (op.destructive) append(" [destructive]")
        if (PagingDefaults.isPaged(op)) append(PAGING_GUIDANCE)
    }

    /** JSON-Schema for the tool input: one property per path/query parameter, plus `body` and `confirm` where applicable. */
    fun build(op: CatalogOp): ToolSchema {
        val required = mutableListOf<String>()
        val properties = buildJsonObject {
            for (p in op.params) {
                put(p.name, annotate(sizeAwareSchema(p, op), p))
                if (p.required) required += p.name
            }
            op.body?.let { body ->
                val schema = buildJsonObject {
                    body.schema.forEach { (k, v) -> if (k != "description") put(k, v) }
                    val original = (body.schema["description"] as? JsonPrimitive)?.content
                    val prefix = if (body.isJson) "Request body (JSON)." else "Request body (${body.contentType})."
                    put("description", if (original.isNullOrBlank()) prefix else "$prefix $original")
                }
                put(CatalogLoader.BODY_PROPERTY, schema)
                if (body.required) required += CatalogLoader.BODY_PROPERTY
            }
            if (op.admin) {
                put(
                    CatalogLoader.CONFIRM_PROPERTY,
                    buildJsonObject {
                        put("type", "string")
                        putJsonArray("enum") { add(JsonPrimitive(CONFIRM_VALUE)) }
                        put("description", "Must be exactly \"$CONFIRM_VALUE\" to acknowledge that this runs a command on the Security Console.")
                    },
                )
                required += CatalogLoader.CONFIRM_PROPERTY
            }
        }
        return ToolSchema(properties = properties, required = required.ifEmpty { null })
    }

    /**
     * The `size` parameter's own description, restated to match what this server actually does — the
     * specification's `default: 10` is not what an omitted `size` yields here, and it declares no
     * maximum at all.
     */
    private fun sizeAwareSchema(p: CatalogParam, op: CatalogOp): JsonObject {
        if (!p.isQuery || p.name != PagingDefaults.SIZE_PARAM) return p.schema
        val original = (p.schema["description"] as? JsonPrimitive)?.content.orEmpty()
        val policy = "Defaults to ${PagingDefaults.DEFAULT_PAGE_SIZE} on this server; values above " +
            "${PagingDefaults.maxSizeFor(op)} are clamped so a page can fit the response budget."
        return buildJsonObject {
            p.schema.forEach { (k, v) -> if (k != "description") put(k, v) }
            put("description", if (original.isBlank()) policy else "$original $policy")
        }
    }

    /** Add a location hint to a parameter's description so the model knows path vs query semantics. */
    private fun annotate(schema: JsonObject, p: CatalogParam): JsonObject = buildJsonObject {
        schema.forEach { (k, v) -> if (k != "description") put(k, v) }
        val original = (schema["description"] as? JsonPrimitive)?.content.orEmpty()
        val hint = if (p.isPath) "Path parameter." else "Query parameter."
        put("description", if (original.isBlank()) hint else "$original ($hint)")
    }
}
