package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.JsonCodec
import com.jitunicornfx.insightvm.mcp.parseWholeNumber
import com.jitunicornfx.insightvm.mcp.seg
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

/** A fully validated, ready-to-send request derived from tool-call arguments. */
data class BoundRequest(
    val method: HttpMethod,
    /** Path with every placeholder substituted by a percent-encoded single segment. */
    val path: String,
    val query: Map<String, List<String>>,
    val jsonBody: JsonElement? = null,
    val rawBody: String? = null,
    val rawContentType: ContentType? = null,
)

/**
 * Binds model-supplied arguments to a [CatalogOp]. Everything the model sends is validated here:
 * unknown argument names are rejected (nothing can be smuggled into the request), scalars are
 * coerced against the declared schema, strings are bounded and may not contain line breaks, the
 * path is built only from the template, and bodies are size- and depth-capped.
 */
object ArgumentBinder {

    const val MAX_STRING_LENGTH = 4096
    const val MAX_BODY_BYTES = 1_048_576
    const val MAX_BODY_DEPTH = 32
    const val MAX_ARRAY_ITEMS = 500

    private val PLACEHOLDER = Regex("\\{([^{}]+)}")
    private val FORBIDDEN_CHARS = charArrayOf('\r', '\n', '\u0000')

    fun bind(op: CatalogOp, args: JsonObject): BoundRequest {
        val known = op.params.map { it.name }.toMutableSet()
        if (op.body != null) known += CatalogLoader.BODY_PROPERTY
        if (op.admin) known += CatalogLoader.CONFIRM_PROPERTY
        val unknown = args.keys - known
        require(unknown.isEmpty()) {
            "Unknown parameter(s) ${unknown.sorted().joinToString(", ") { "'$it'" }}. " +
                "Accepted: ${known.sorted().joinToString(", ")}."
        }

        val pathValues = HashMap<String, String>()
        val query = LinkedHashMap<String, List<String>>()
        for (p in op.params) {
            val raw = args[p.name]?.takeUnless { it is JsonNull }
            if (raw == null) {
                require(!p.required) { "Missing required parameter '${p.name}'." }
                continue
            }
            val values = if (p.array) bindArray(p, raw) else listOf(coerceScalar(p.schema, raw, p.name))
            if (p.isPath) {
                val value = values.single()
                require(value.isNotEmpty()) { "Path parameter '${p.name}' must not be empty." }
                pathValues[p.name] = value
            } else {
                query[p.name] = values
            }
        }
        val path = substitutePath(op.path, pathValues)

        var jsonBody: JsonElement? = null
        var rawBody: String? = null
        var rawType: ContentType? = null
        op.body?.let { body ->
            val element = args[CatalogLoader.BODY_PROPERTY]?.takeUnless { it is JsonNull }
            if (element == null) {
                require(!body.required) { "Missing required parameter 'body'." }
            } else if (body.isJson) {
                jsonBody = validateJsonBody(body, element)
            } else {
                val text = (element as? JsonPrimitive)?.takeIf { it.isString }?.content
                    ?: throw IllegalArgumentException("Parameter 'body' must be a string for this operation.")
                require(text.toByteArray(Charsets.UTF_8).size <= MAX_BODY_BYTES) { "Parameter 'body' exceeds $MAX_BODY_BYTES bytes." }
                rawBody = text
                rawType = ContentType.parse(body.contentType)
            }
        }

        return BoundRequest(
            method = HttpMethod.parse(op.method),
            path = path,
            query = query,
            jsonBody = jsonBody,
            rawBody = rawBody,
            rawContentType = rawType,
        )
    }

    private fun bindArray(p: CatalogParam, raw: JsonElement): List<String> {
        val itemSchema = p.schema["items"] as? JsonObject ?: JsonObject(emptyMap())
        val elements: List<JsonElement> = when (raw) {
            is JsonArray -> raw
            is JsonPrimitive -> listOf(raw) // a lone scalar is accepted as a one-element array
            else -> throw IllegalArgumentException("Parameter '${p.name}' must be an array.")
        }
        require(elements.size <= MAX_ARRAY_ITEMS) { "Parameter '${p.name}' has more than $MAX_ARRAY_ITEMS items." }
        return elements.map { coerceScalar(itemSchema, it, p.name) }
    }

    /** Coerce a scalar argument to its wire string according to [schema]'s `type`/`enum`. */
    internal fun coerceScalar(schema: JsonObject, value: JsonElement, name: String): String {
        val primitive = value as? JsonPrimitive
            ?: throw IllegalArgumentException("Parameter '$name' must be a scalar value.")
        val type = (schema["type"] as? JsonPrimitive)?.contentOrNull ?: "string"
        val text = when (type) {
            "integer" -> parseWholeNumber(primitive.content)?.toString()
                ?: throw IllegalArgumentException("Parameter '$name' must be an integer (got '${primitive.content.take(40)}').")
            "number" -> {
                primitive.content.trim().toDoubleOrNull()?.toString()
                    ?: throw IllegalArgumentException("Parameter '$name' must be a number.")
            }
            "boolean" -> {
                val b = primitive.booleanOrNull ?: when (primitive.content.trim().lowercase()) {
                    "true" -> true
                    "false" -> false
                    else -> throw IllegalArgumentException("Parameter '$name' must be true or false.")
                }
                b.toString()
            }
            else -> primitive.content
        }
        require(text.length <= MAX_STRING_LENGTH) { "Parameter '$name' exceeds $MAX_STRING_LENGTH characters." }
        require(text.none { it in FORBIDDEN_CHARS }) { "Parameter '$name' must not contain line breaks or NUL." }
        (schema["enum"] as? JsonArray)?.let { allowed ->
            val options = allowed.map { it.jsonPrimitive.content }
            require(text in options) { "Parameter '$name' must be one of: ${options.joinToString(", ")}." }
        }
        return text
    }

    /** Replace each `{placeholder}` with the percent-encoded value; every placeholder must be supplied. */
    internal fun substitutePath(template: String, values: Map<String, String>): String =
        PLACEHOLDER.replace(template) { match ->
            val key = match.groupValues[1]
            val value = values[key] ?: throw IllegalArgumentException("Missing required parameter '$key'.")
            seg(value)
        }

    private fun validateJsonBody(body: CatalogBody, element: JsonElement): JsonElement {
        val expected = (body.schema["type"] as? JsonPrimitive)?.contentOrNull ?: "object"
        when (expected) {
            "object" -> require(element is JsonObject) { "Parameter 'body' must be a JSON object for this operation." }
            "array" -> require(element is JsonArray) { "Parameter 'body' must be a JSON array for this operation." }
            "string" -> require(element is JsonPrimitive && element.isString) { "Parameter 'body' must be a JSON string for this operation." }
            else -> Unit
        }
        require(depthOf(element) <= MAX_BODY_DEPTH) { "Parameter 'body' is nested deeper than $MAX_BODY_DEPTH levels." }
        val encoded = JsonCodec.compact.encodeToString(JsonElement.serializer(), element)
        require(encoded.toByteArray(Charsets.UTF_8).size <= MAX_BODY_BYTES) { "Parameter 'body' exceeds $MAX_BODY_BYTES bytes." }
        return element
    }

    /** Nesting depth of a JSON value (iterative, so hostile inputs cannot overflow the stack). */
    internal fun depthOf(element: JsonElement): Int {
        var max = 0
        val stack = ArrayDeque<Pair<JsonElement, Int>>()
        stack.addLast(element to 1)
        while (stack.isNotEmpty()) {
            val (e, d) = stack.removeLast()
            if (d > max) max = d
            if (d > MAX_BODY_DEPTH) return d
            when (e) {
                is JsonObject -> e.values.forEach { stack.addLast(it to d + 1) }
                is JsonArray -> e.forEach { stack.addLast(it to d + 1) }
                else -> Unit
            }
        }
        return max
    }
}
