package com.jitunicornfx.insightvm.mcp.testutil

import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.InputSchemaBuilder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull

/** Produces a plausible argument value for every property of a tool's JSON-Schema input. */
object SchemaExampleSynthesizer {

    const val INT_EXAMPLE = 7L
    const val STRING_EXAMPLE = "x-1"

    /** One value per declared property (required or not), so every parameter path gets exercised. */
    fun argsFor(properties: JsonObject): JsonObject = buildJsonObject {
        properties.forEach { (name, schema) ->
            put(name, valueFor(name, schema as JsonObject, depth = 0))
        }
    }

    fun valueFor(name: String, schema: JsonObject, depth: Int): JsonElement {
        if (name == CatalogLoader.CONFIRM_PROPERTY) return JsonPrimitive(InputSchemaBuilder.CONFIRM_VALUE)
        (schema["enum"] as? JsonArray)?.firstOrNull()?.let { return it }
        return when ((schema["type"] as? JsonPrimitive)?.contentOrNull) {
            "integer" -> JsonPrimitive(INT_EXAMPLE)
            "number" -> JsonPrimitive(1.5)
            "boolean" -> JsonPrimitive(true)
            "array" -> {
                val items = schema["items"] as? JsonObject ?: JsonObject(mapOf("type" to JsonPrimitive("string")))
                JsonArray(listOf(valueFor(name, items, depth + 1)))
            }
            "object" -> {
                val props = schema["properties"] as? JsonObject
                if (props == null || depth > 2) {
                    JsonObject(mapOf("k" to JsonPrimitive("v")))
                } else {
                    buildJsonObject { props.forEach { (n, s) -> put(n, valueFor(n, s as JsonObject, depth + 1)) } }
                }
            }
            else -> JsonPrimitive(STRING_EXAMPLE)
        }
    }
}
