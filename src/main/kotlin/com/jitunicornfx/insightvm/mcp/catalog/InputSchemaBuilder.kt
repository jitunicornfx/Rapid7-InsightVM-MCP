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
    }

    /** JSON-Schema for the tool input: one property per path/query parameter, plus `body` and `confirm` where applicable. */
    fun build(op: CatalogOp): ToolSchema {
        val required = mutableListOf<String>()
        val properties = buildJsonObject {
            for (p in op.params) {
                put(p.name, annotate(p.schema, p))
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

    /** Add a location hint to a parameter's description so the model knows path vs query semantics. */
    private fun annotate(schema: JsonObject, p: CatalogParam): JsonObject = buildJsonObject {
        schema.forEach { (k, v) -> if (k != "description") put(k, v) }
        val original = (schema["description"] as? JsonPrimitive)?.content.orEmpty()
        val hint = if (p.isPath) "Path parameter." else "Query parameter."
        put("description", if (original.isBlank()) hint else "$original ($hint)")
    }
}
