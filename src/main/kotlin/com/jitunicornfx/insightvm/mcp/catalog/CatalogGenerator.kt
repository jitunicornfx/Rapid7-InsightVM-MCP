package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.Rapid7Client
import io.ktor.http.BadContentTypeFormatException
import io.ktor.http.ContentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.system.exitProcess

/**
 * Generates the tool catalog (`src/main/resources/catalog/{v3,v4}.json`) and the console's
 * search-criteria reference (`search-criteria.json`) from the bundled OpenAPI documents in `specs/`.
 * The runtime registers one tool per catalog entry and never parses the raw specifications; output
 * is deterministic so `--check` can detect drift.
 *
 * Run through Gradle: `./gradlew generateCatalog` (regenerate) / `./gradlew verifyCatalog` (drift
 * check, part of `check`). The rules below are documented in `docs/CATALOG.md`.
 */
object CatalogGenerator {

    const val GENERATOR_VERSION = "CatalogGenerator.kt@1"
    const val MAX_DESCRIPTION = 600
    const val MAX_PROPERTY_DESCRIPTION = 400

    /**
     * The characters an operation description may lose to [MAX_DESCRIPTION] before generation fails.
     * A cut that large drops content, not a tail: updateTagSearchCriteria's copy of the search-criteria
     * tables lost 5,300 characters mid-row, and nothing said so.
     */
    const val MAX_DESCRIPTION_CUT = 1_000

    /** The v4 search-criteria note appended to the search bodies; it runs to about 1,000 characters. */
    const val MAX_SEARCH_NOTE = 1_500

    /** The third generated file: the console's search-criteria tables. */
    const val SEARCH_CRITERIA_FILE = "search-criteria.json"

    /** A field merged in from a discriminator subtype is one of many on the same object, so its text is kept shorter. */
    const val MAX_MERGED_DESCRIPTION = 200
    const val MAX_SUMMARY = 120

    /** Nested `$ref`s inlined along one path before the next is replaced with an opaque object. */
    const val MAX_DEPTH = 8

    private val HTTP_METHODS = listOf("get", "post", "put", "delete", "patch")

    /**
     * The `operationId` verbs of writes that only add: a new record, a membership, a scan, a report
     * instance. MCP defines `destructiveHint: false` as "only additive updates", so every other write
     * is destructive, and the default is destructive rather than safe: a PUT that replaces a list
     * deletes whatever the new list omits (`set_site_scan_schedules` with `[]` does what
     * `delete_all_site_scan_schedules` does), and a status change, password reset or 2FA reset
     * overwrites state. A new verb in a future spec is therefore flagged until someone looks at it.
     * The verb must end at a camel-case boundary, so `addendum` is not `add`.
     */
    private val ADDITIVE_OPID = Regex("^(create|add|start|generate|tag|reconnect)[A-Z]")
    private val ADMIN_OPS = setOf("POST" to "/api/3/administration/commands")
    private val STRIP_KEYS = setOf("example", "examples", "xml", "title", "deprecated", "discriminator", "externalDocs")
    private val COMPOSITIONS = setOf("allOf", "oneOf", "anyOf")
    private val SCALAR_TYPES = setOf("string", "integer", "number", "boolean")

    /**
     * The `format` values OpenAPI and JSON Schema define that the specifications use. Anything else is
     * prose in the wrong field: v4's `sort` declares `format: "<property>[,ASC|DESC]"`, which its
     * description already says, and a client may read an unknown format as a constraint.
     */
    private val KNOWN_FORMATS = setOf("int32", "int64", "float", "double", "byte", "binary", "date", "date-time", "password", "uuid", "email", "uri")

    /** The string formats that carry a file rather than text: raw octets, and base64-encoded octets. */
    private val FILE_FORMATS = setOf("binary", "byte")

    /**
     * Spec type defects, corrected on the component before anything is inlined: component, then
     * property, then the schema it should have had. RangeResource.from and RiskTrendResource.from are
     * declared an object whose enum ends in the literal "<date>", which no value can satisfy; the API
     * takes a duration or a date, as a string.
     */
    private val PROPERTY_OVERRIDES: Map<String, Map<String, JsonObject>> = run {
        val trendStart = JsonObject(
            mapOf(
                "type" to JsonPrimitive("string"),
                "description" to JsonPrimitive("The start of the trend: a duration (P1Y, P6M, P3M or P1M) or an ISO-8601 date."),
            ),
        )
        mapOf("RangeResource" to mapOf("from" to trendStart), "RiskTrendResource" to mapOf("from" to trendStart))
    }

    /**
     * Query parameters the APIs accept repeated (`sort=a&sort=b`). v3 declares `sort` an array; v4
     * declares it a string, although its own description says multiple sort criteria are given as
     * multiple sort query parameters.
     */
    private val REPEATED_QUERY_PARAMS = setOf("sort")

    /**
     * Operations whose declared JSON body cannot work, so the tool offers none. activateLicense
     * declares the license file as a JSON property of format binary, and the property's own text says
     * it must be sent as multipart/form-data, which this server never sends. Its `key` query
     * parameter still activates a license.
     */
    private val BODYLESS_OPS = setOf("POST" to "/api/3/administration/license")

    /** The v3 filter components the search-criteria reference applies to: asset criteria, then discovery criteria. */
    private const val ASSET_FILTER = "SwaggerSearchCriteriaFilter"
    private const val DISCOVERY_FILTER = "SwaggerDiscoverySearchCriteriaFilter"

    /**
     * What replaces the specifications' links to their own search-criteria reference. The link points
     * into `info.description`, which no tool carries, so the model was told to "See Search Criteria"
     * and had nowhere to look.
     */
    const val ASSET_CRITERIA_POINTER =
        "Call ${CatalogTools.SEARCH_CRITERIA_TOOL} for the operators each field accepts and the value each operator takes."
    const val DISCOVERY_CRITERIA_POINTER =
        "Call ${CatalogTools.SEARCH_CRITERIA_TOOL} with kind \"discovery\" for the fields each connection type supports, " +
            "the operators each accepts and the value each operator takes."

    /** `See <a href="#section/Responses/SearchCriteria">Search Criteria</a> for more information …` and its discovery twin. */
    private val CRITERIA_LINK =
        Regex("See (?:the )?<a href=\"#section/Responses/(Discovery)?SearchCriteria\">[^<]*</a> for more information[^.]*\\.")

    /**
     * Operations whose description is a copy of the search-criteria tables, which the cap cut
     * mid-row. Each keeps its first sentence and points at the tool that serves the whole reference.
     */
    private val CRITERIA_TABLE_OPS = setOf("PUT" to "/api/3/tags/{id}/search_criteria")

    /**
     * Operations whose description may lose more than [MAX_DESCRIPTION_CUT] characters. Empty: an
     * entry is a decision that the text past the cap does not matter, and none has been made.
     */
    private val LONG_DESCRIPTION_OPS = emptySet<Pair<String, String>>()

    /**
     * The v4 searches whose body gains the introduction's "Search Criteria" section. It is the only
     * place v4 says that a `vulnerability` chunk alone does not narrow the assets returned, and it
     * holds the query-language examples.
     *
     * Only the asset search: the section is about its two chunks, `asset` and `vulnerability`, and its
     * examples send `{"asset": ...}`. The vulnerabilities search takes a VulnerabilitySearch body with a
     * `vulnerability` chunk alone, so the same text there told the model to send a property that
     * endpoint does not define.
     */
    private val SEARCH_NOTE_OPS = setOf("POST" to "/v4/integration/assets")

    /** One spec → one catalog file. */
    data class Source(val family: ApiFamily, val specFile: String, val outputFile: String)

    val SOURCES = listOf(
        Source(ApiFamily.CONSOLE, "insightvm-console-v3.json", "v3.json"),
        Source(ApiFamily.CLOUD, "insightvm-cloud-v4.json", "v4.json"),
    )

    class CatalogGenerationException(message: String) : RuntimeException(message)

    private val output = Json {
        prettyPrint = true
        prettyPrintIndent = " "
        encodeDefaults = true
    }

    // ------------------------------------------------------------------ text helpers

    /**
     * The HTML elements the specifications use for layout: tables, lists, emphasis, links, line
     * breaks. Only these are stripped. Anything else in angle brackets is prose, such as the
     * `<property>` in v4's sort format or `<host>:<port>`, and deleting it changes what the text says.
     */
    private val TAG = Regex("</?(a|b|br|code|div|em|i|li|ol|p|pre|span|strong|table|tbody|td|th|thead|tr|ul)\\b[^>]*>", RegexOption.IGNORE_CASE)

    /**
     * HTML opens markup only at a `<` followed by a letter, `/`, `!` or `?`. Such a token, closed or
     * not, is neutralised with `‹›`. Every other `<` and `>` is left alone: the v4 query language is
     * written with them (`cvss_score >= 9`), and `›=` is not an operator.
     */
    private val TAG_LIKE = Regex("<([A-Za-z/!?][^<>]*)>")
    private val MARKUP_OPENER = Regex("<(?=[A-Za-z/!?])")

    /** v4 text that is only unrendered template keys, such as `${scanid.id.description}, ${scan.id.id.description}`. */
    private val UNRENDERED = Regex("\\\$\\{[^}]+}(, \\\$\\{[^}]+})*")
    private val WS = Regex("\\s+")
    private val FIRST_SENTENCE = Regex("^.*?[.!?](?=\\s|$)")
    private val CONTROL = Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]")
    private val ENTITY = Regex("&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z][a-zA-Z0-9]{0,31});")

    /**
     * The named entities the specifications actually use. Anything else is a hard error rather than
     * a silent pass-through, so a future specification cannot quietly degrade a description.
     */
    private val NAMED_ENTITIES = mapOf(
        "amp" to "&", "lt" to "<", "gt" to ">", "quot" to "\"", "apos" to "'", "nbsp" to " ",
        "check" to "✓", "copy" to "©", "reg" to "®", "trade" to "™",
        "mdash" to "—", "ndash" to "–", "hellip" to "…",
    )

    internal fun unescapeEntities(text: String): String = ENTITY.replace(text) { m ->
        val body = m.groupValues[1]
        when {
            body.startsWith("#x") || body.startsWith("#X") -> String(Character.toChars(body.substring(2).toInt(16)))
            body.startsWith("#") -> String(Character.toChars(body.substring(1).toInt()))
            else -> NAMED_ENTITIES[body] ?: throw CatalogGenerationException("unsupported HTML entity &$body; in specification text")
        }
    }

    /**
     * Point a link to the search-criteria reference at the tool that serves it, strip layout HTML,
     * decode entities, drop control chars, collapse whitespace, neutralise anything that could open
     * markup, cap length. Text that is only unrendered template keys is no text. Tags are stripped
     * before entities are decoded, so an encoded `&lt;script&gt;` is neutralised, never stripped or
     * passed through.
     */
    internal fun cleanText(text: String?, limit: Int = MAX_DESCRIPTION): String {
        if (text.isNullOrEmpty()) return ""
        var s = CRITERIA_LINK.replace(text) { if (it.groupValues[1].isEmpty()) ASSET_CRITERIA_POINTER else DISCOVERY_CRITERIA_POINTER }
        s = TAG.replace(s, " ")
        s = unescapeEntities(s)
        s = CONTROL.replace(s, "")
        s = WS.replace(s, " ").trim()
        if (UNRENDERED.matches(s)) return ""
        s = TAG_LIKE.replace(s) { "‹${it.groupValues[1]}›" }
        s = MARKUP_OPENER.replace(s, "‹")
        return cap(s, limit)
    }

    /** [text] cut to [limit] characters, the cut marked with an ellipsis. */
    private fun cap(text: String, limit: Int): String =
        if (text.length > limit) text.substring(0, limit - 1).trimEnd() + "…" else text

    private val CAMEL_1 = Regex("(.)([A-Z][a-z]+)")
    private val CAMEL_2 = Regex("([a-z0-9])([A-Z])")
    private val NON_ALNUM = Regex("[^a-zA-Z0-9]+")
    private val MULTI_UNDERSCORE = Regex("_+")

    internal fun snakeCase(opId: String): String {
        var s = CAMEL_1.replace(opId, "$1_$2")
        s = CAMEL_2.replace(s, "$1_$2")
        s = NON_ALNUM.replace(s, "_").lowercase().trim('_')
        return MULTI_UNDERSCORE.replace(s, "_")
    }

    // ------------------------------------------------------------------ schema inlining

    /** Inlines against [components], with [overrides] (component → property → schema) applied first. */
    private class Inliner(components: JsonObject?, overrides: Map<String, Map<String, JsonObject>>) {
        private val schemas: JsonObject = withOverrides(components?.get("schemas")?.jsonObject ?: JsonObject(emptyMap()), overrides)

        private fun resolve(ref: String): Pair<String, JsonObject> {
            val prefix = "#/components/schemas/"
            if (!ref.startsWith(prefix)) throw CatalogGenerationException("unsupported \$ref: $ref")
            val name = ref.removePrefix(prefix)
            val target = schemas[name] as? JsonObject ?: throw CatalogGenerationException("unknown schema: $name")
            return name to target
        }

        /**
         * [schema] with its chain of `$ref`s followed to the component it names; nothing below that is
         * inlined. Null for a cycle of bare `$ref`s, which describes no schema at all.
         */
        fun deref(schema: JsonElement?): JsonObject? {
            var node = schema as? JsonObject ?: return null
            val seen = HashSet<String>()
            while (true) {
                val ref = (node["\$ref"] as? JsonPrimitive)?.contentOrNull ?: return node
                val (name, target) = resolve(ref)
                if (!seen.add(name)) return null
                node = target
            }
        }

        /**
         * Inline [schema]: resolve `$ref`s, drop documentation-only and server-assigned keys, clean the
         * text. [stack] is the chain of components being inlined; it stops cycles, and bounds depth by
         * `$ref`s rather than JSON nesting, so a short chain whose leaf sits deep inside arrays of
         * objects (create_asset's WebPage) is still inlined.
         *
         * [nested] is false only for the root a caller passes in. The caller types that itself, because
         * the right type depends on the use: an object-shaped path parameter is still one string on the
         * wire. Every node below the root gets a missing type inferred, so a client that checks
         * arguments against the schema sees an array as an array.
         */
        fun inline(schema: JsonElement?, stack: List<String> = emptyList(), nested: Boolean = false): JsonElement? {
            if (schema !is JsonObject) return schema
            schema["\$ref"]?.let { refElement ->
                val (name, target) = resolve(refElement.jsonPrimitive.content)
                if (name in stack || stack.size >= MAX_DEPTH) {
                    return JsonObject(
                        mapOf(
                            "type" to JsonPrimitive("object"),
                            "description" to JsonPrimitive("$name (nested object; see the Rapid7 API documentation)"),
                        ),
                    )
                }
                val merged = inline(target, stack + name, nested)
                val extra = cleanText((schema["description"] as? JsonPrimitive)?.contentOrNull, MAX_PROPERTY_DESCRIPTION)
                return if (merged is JsonObject && extra.isNotEmpty()) JsonObject(merged + ("description" to JsonPrimitive(extra))) else merged
            }

            val out = LinkedHashMap<String, JsonElement>()
            for ((key, value) in schema) {
                when {
                    key in STRIP_KEYS -> Unit
                    key == "properties" && value is JsonObject -> {
                        val props = LinkedHashMap<String, JsonElement>()
                        for ((pname, pschema) in value) {
                            if (pschema is JsonObject && pschema["readOnly"]?.jsonPrimitive?.booleanOrNull == true) continue
                            props[pname] = inline(pschema, stack, nested = true) ?: pschema
                        }
                        out["properties"] = JsonObject(props)
                    }
                    key == "items" -> out["items"] = inline(value, stack, nested = true) ?: value
                    key == "additionalProperties" -> out["additionalProperties"] = if (value is JsonObject) inline(value, stack, nested = true) ?: value else value
                    key in COMPOSITIONS && value is JsonArray -> out[key] = JsonArray(value.map { inline(it, stack, nested = true) ?: it })
                    key == "description" -> cleanText(value.jsonPrimitive.contentOrNull, MAX_PROPERTY_DESCRIPTION).takeIf { it.isNotEmpty() }?.let { out["description"] = JsonPrimitive(it) }
                    key == "format" -> if ((value as? JsonPrimitive)?.contentOrNull in KNOWN_FORMATS) out["format"] = value
                    key == "readOnly" -> Unit
                    else -> out[key] = value
                }
            }
            mappedDiscriminator(schema)?.let { (property, mapping) -> mergeSubtypes(out, property, mapping, stack) }
            val required = out["required"]
            if (out["properties"] is JsonObject && required is JsonArray) {
                val props = out["properties"]!!.jsonObject
                val kept = required.filter { it.jsonPrimitive.content in props }
                if (kept.isEmpty()) out.remove("required") else out["required"] = JsonArray(kept)
            }
            // An array whose items repeat its own description pays for the same text twice in every tools/list.
            val items = out["items"] as? JsonObject
            if (items != null && "description" in items && items["description"] == out["description"]) out["items"] = JsonObject(items - "description")
            if (nested && "type" !in out && COMPOSITIONS.none { it in out }) inferType(out)?.let { out["type"] = JsonPrimitive(it) }
            return JsonObject(out)
        }

        /**
         * The discriminator property and mapping to flatten, or null when there is no discriminator or
         * a oneOf/anyOf already lists the subtypes. One this generator cannot flatten fails generation
         * rather than silently hiding its subtypes' fields.
         */
        private fun mappedDiscriminator(schema: JsonObject): Pair<String, JsonObject>? {
            val discriminator = schema["discriminator"] as? JsonObject ?: return null
            if ("oneOf" in schema || "anyOf" in schema) return null
            val property = (discriminator["propertyName"] as? JsonPrimitive)?.contentOrNull
            val mapping = discriminator["mapping"] as? JsonObject
            if (property == null || mapping.isNullOrEmpty()) {
                throw CatalogGenerationException("discriminator without both a propertyName and a mapping is not supported")
            }
            return property to mapping
        }

        /**
         * A discriminator whose subtypes are named only in its `mapping` hides every subtype field once
         * the discriminator is stripped. SharedCredentialAccount declares only `service`, so the model
         * could never learn `username`, `pemKey` or `permissionElevation`, and could not build a
         * working SSH or SNMP credential. The union of the subtypes' properties is merged into the base
         * instead: the base's own properties win, otherwise the first definition does. Each merged field
         * names the values it belongs to and keeps shorter text, and the base description gains the
         * field list for each value. Subtype `required` lists are not merged, since each binds only its
         * own value. A subtype that is itself discriminated fails generation.
         */
        private fun mergeSubtypes(out: MutableMap<String, JsonElement>, property: String, mapping: JsonObject, stack: List<String>) {
            val base = (out["properties"] as? JsonObject).orEmpty()
            val merged = LinkedHashMap<String, JsonObject>()
            val valuesOf = HashMap<String, MutableList<String>>()
            val fieldsByValue = mutableListOf<String>()
            for ((value, ref) in mapping) {
                val (name, target) = resolve(ref.jsonPrimitive.content)
                if ("discriminator" in target) throw CatalogGenerationException("nested discriminator in $name is not supported")
                val subtype = inline(target, stack + name, nested = true) as JsonObject
                val fields = (subtype["properties"] as? JsonObject).orEmpty().filterKeys { it !in base }
                fieldsByValue += "$value: " + fields.keys.filter { it != property }.joinToString(", ").ifEmpty { "none" }
                for ((field, fieldSchema) in fields) {
                    merged.putIfAbsent(field, fieldSchema.jsonObject)
                    valuesOf.getOrPut(field) { mutableListOf() } += value
                }
            }
            val props = LinkedHashMap(base)
            for ((field, fieldSchema) in merged) {
                val own = (fieldSchema["description"] as? JsonPrimitive)?.contentOrNull?.let { cap(it, MAX_MERGED_DESCRIPTION) + " " }.orEmpty()
                val text = "$own($property: ${valuesOf.getValue(field).joinToString(", ")})"
                props[field] = JsonObject(fieldSchema + ("description" to JsonPrimitive(text)))
            }
            out["properties"] = JsonObject(props)
            val lead = (out["description"] as? JsonPrimitive)?.contentOrNull?.let { "$it " }.orEmpty()
            out["description"] = JsonPrimitive("${lead}Fields by $property: ${fieldsByValue.joinToString("; ")}.")
        }
    }

    /** [schemas] with [overrides] applied to the components they name. */
    private fun withOverrides(schemas: JsonObject, overrides: Map<String, Map<String, JsonObject>>): JsonObject = JsonObject(
        schemas.mapValues { (name, schema) ->
            val fixes = overrides[name]
            val props = (schema as? JsonObject)?.get("properties") as? JsonObject
            if (fixes == null || props == null) schema else JsonObject(schema.jsonObject + ("properties" to JsonObject(props.mapValues { (p, s) -> fixes[p] ?: s })))
        },
    )

    /**
     * The search-criteria filter components with [reference] applied. `field` and `operator` gain an
     * `enum` of the names the tables list: for discovery, the union over every connection type. The
     * value properties lose the `object` type the spec gives them, which no operator takes: a value is
     * a string or a number, a list goes in `values`, and a bound is a string or a number. Once the reference exists, a
     * filter component or property it cannot find fails generation rather than going unconstrained.
     */
    private fun criteriaOverrides(components: JsonObject?, reference: SearchCriteriaReference?): Map<String, Map<String, JsonObject>> {
        if (reference == null) return emptyMap()
        val schemas = components?.get("schemas") as? JsonObject
        fun filter(component: String, fields: List<CriteriaField>): Map<String, JsonObject> {
            val props = (schemas?.get(component) as? JsonObject)?.get("properties") as? JsonObject
                ?: throw CatalogGenerationException("the search-criteria reference applies to $component, which has no properties")
            fun prop(name: String) = props[name] as? JsonObject
                ?: throw CatalogGenerationException("$component has no '$name' property for the search-criteria reference")
            fun enumOf(names: List<String>) = JsonArray(names.distinct().map(::JsonPrimitive))
            fun untyped(name: String, kinds: String): JsonObject {
                val schema = prop(name)
                val text = listOfNotNull((schema["description"] as? JsonPrimitive)?.contentOrNull, "A $kinds, depending on the operator.")
                return JsonObject(schema - "type" + ("description" to JsonPrimitive(text.joinToString(" "))))
            }
            val values = prop("values")
            // `value` is "the single value"; a list goes in `values`, named for the operators that read one,
            // since the spec's own operator table says the opposite (see SearchCriteriaTables).
            val listOperators = fields.flatMap { it.operators }.distinct().filter { reference.operators[it]?.containsKey("values") == true }
            val valuesText = listOfNotNull(
                (values["description"] as? JsonPrimitive)?.contentOrNull,
                listOperators.takeIf { it.isNotEmpty() }?.let { "Used by the operators that take a list: ${it.joinToString(", ")}." },
            ).joinToString(" ")
            return mapOf(
                "field" to JsonObject(prop("field") + ("enum" to enumOf(fields.map { it.name }))),
                "operator" to JsonObject(prop("operator") + ("enum" to enumOf(fields.flatMap { it.operators }))),
                "value" to untyped("value", "string or number"),
                "lower" to untyped("lower", "string or number"),
                "upper" to untyped("upper", "string or number"),
                // The item's own text only repeats the array's, so it goes with the object type.
                "values" to JsonObject(
                    values + ("description" to JsonPrimitive(valuesText)) +
                        ("items" to JsonObject(((values["items"] as? JsonObject) ?: JsonObject(emptyMap())) - "type" - "description")),
                ),
            )
        }
        return mapOf(
            ASSET_FILTER to filter(ASSET_FILTER, reference.asset),
            DISCOVERY_FILTER to filter(DISCOVERY_FILTER, reference.discovery.flatMap { it.fields }),
        )
    }

    /** The type a nested schema node plainly has but does not declare, or null when nothing says. */
    private fun inferType(schema: Map<String, JsonElement>): String? {
        val format = (schema["format"] as? JsonPrimitive)?.contentOrNull
        val options = schema["enum"] as? JsonArray
        return when {
            "items" in schema -> "array"
            "properties" in schema || "additionalProperties" in schema -> "object"
            options != null -> if (options.all { it is JsonPrimitive && it.isString }) "string" else null
            format == "int32" || format == "int64" -> "integer"
            format == "float" || format == "double" -> "number"
            format in KNOWN_FORMATS -> "string"
            else -> null
        }
    }

    // ------------------------------------------------------------------ parameters / bodies

    private fun normalizeParamSchema(raw: JsonElement?, inliner: Inliner): Pair<JsonObject, Boolean> {
        val schema = LinkedHashMap((inliner.inline(raw ?: JsonObject(emptyMap())) as? JsonObject) ?: JsonObject(emptyMap()))
        if ("type" !in schema) {
            val default = schema["default"] as? JsonPrimitive
            schema["type"] = JsonPrimitive(
                when {
                    "enum" in schema -> "string"
                    "items" in schema -> "array"
                    (schema["format"] as? JsonPrimitive)?.contentOrNull in setOf("int32", "int64") -> "integer"
                    default != null && default.booleanOrNull != null && !default.isString -> "boolean"
                    default != null && !default.isString && default.content.toLongOrNull() != null -> "integer"
                    else -> "string"
                },
            )
        }
        val isArray = (schema["type"] as? JsonPrimitive)?.contentOrNull == "array"
        if (isArray) {
            var items = LinkedHashMap((schema["items"] as? JsonObject)?.takeIf { it.isNotEmpty() } ?: JsonObject(mapOf("type" to JsonPrimitive("string"))))
            schema["enum"]?.let { enum ->
                if ("enum" !in items) {
                    items["enum"] = enum
                    schema.remove("enum")
                }
            }
            if ("type" !in items) items["type"] = JsonPrimitive("string")
            schema["items"] = JsonObject(items)
        }
        // v4 wraps several path identifiers in a component (ScanId, AssetKey) and v3 some role and
        // source ids (RoleNaturalID); the value is still one string, so their object shape is noise.
        if ((schema["type"] as? JsonPrimitive)?.contentOrNull in SCALAR_TYPES) {
            schema.remove("properties")
            schema.remove("required")
        }
        return JsonObject(schema) to isArray
    }

    /** [raw] as an array of itself, unless it already is one. */
    private fun repeated(raw: JsonElement?): JsonElement {
        val schema = raw as? JsonObject ?: JsonObject(emptyMap())
        if ((schema["type"] as? JsonPrimitive)?.contentOrNull == "array") return schema
        return JsonObject(mapOf("type" to JsonPrimitive("array"), "items" to schema))
    }

    private fun buildParams(op: JsonObject, inliner: Inliner, family: ApiFamily): List<CatalogParam> {
        val params = mutableListOf<CatalogParam>()
        val seen = HashSet<String>()
        val opId = op["operationId"]?.jsonPrimitive?.contentOrNull
        for (p in (op["parameters"] as? JsonArray).orEmpty()) {
            val param = p.jsonObject
            if ("\$ref" in param) throw CatalogGenerationException("parameter \$ref not supported")
            val where = param["in"]?.jsonPrimitive?.contentOrNull
            val name = param["name"]?.jsonPrimitive?.contentOrNull ?: continue
            if (where != "path" && where != "query") continue
            if (family == ApiFamily.CLOUD && where == "path" && name == "region") continue
            if (name == CatalogLoader.BODY_PROPERTY) throw CatalogGenerationException("parameter named 'body' collides with the request body property ($opId)")
            if (!seen.add(name)) throw CatalogGenerationException("duplicate parameter $name in $opId")
            val raw = if (where == "query" && name in REPEATED_QUERY_PARAMS) repeated(param["schema"]) else param["schema"]
            val (schemaBase, isArray) = normalizeParamSchema(raw, inliner)
            val desc = cleanText(param["description"]?.jsonPrimitive?.contentOrNull, MAX_PROPERTY_DESCRIPTION)
            val schema = if (desc.isNotEmpty()) JsonObject(schemaBase + ("description" to JsonPrimitive(desc))) else schemaBase
            params += CatalogParam(
                name = name,
                `in` = where,
                required = (param["required"]?.jsonPrimitive?.booleanOrNull == true) || where == "path",
                array = isArray,
                schema = schema,
            )
        }
        return params
    }

    private fun buildBody(op: JsonObject, method: String, path: String, inliner: Inliner): CatalogBody? {
        if ((method to path) in BODYLESS_OPS) return null
        val rb = op["requestBody"] as? JsonObject ?: return null
        val content = rb["content"] as? JsonObject ?: JsonObject(emptyMap())
        val required = rb["required"]?.jsonPrimitive?.booleanOrNull == true
        content["application/json"]?.let { json ->
            val inlined = inliner.inline(json.jsonObject["schema"] ?: JsonObject(emptyMap())) as? JsonObject
            val schema = LinkedHashMap(inlined?.takeIf { it.isNotEmpty() } ?: JsonObject(mapOf("type" to JsonPrimitive("object"))))
            if ("type" !in schema) schema["type"] = JsonPrimitive("object")
            // A file declared as a JSON property can never be sent as JSON. A new one must be looked at
            // and added to BODYLESS_OPS, not published as a tool that cannot work.
            if (declaresBinary(JsonObject(schema))) {
                throw CatalogGenerationException("JSON request body declares a format: binary property in ${op["operationId"]}; a file cannot be sent as JSON")
            }
            return CatalogBody("application/json", required, JsonObject(schema))
        }
        if ("text/plain" in content) {
            val schema = LinkedHashMap<String, JsonElement>(mapOf("type" to JsonPrimitive("string")))
            val desc = cleanText(rb["description"]?.jsonPrimitive?.contentOrNull, MAX_PROPERTY_DESCRIPTION)
            if (desc.isNotEmpty()) schema["description"] = JsonPrimitive(desc)
            return CatalogBody("text/plain", required, JsonObject(schema))
        }
        throw CatalogGenerationException("unsupported request body content types ${content.keys} in ${op["operationId"]}")
    }

    /** Whether any schema node under [element] declares `format: binary`. */
    private fun declaresBinary(element: JsonElement): Boolean = when (element) {
        is JsonObject -> (element["format"] as? JsonPrimitive)?.contentOrNull == "binary" || element.values.any { declaresBinary(it) }
        is JsonArray -> element.any { declaresBinary(it) }
        else -> false
    }

    /**
     * The first 2xx response: its content type, and whether its body is a file rather than text.
     *
     * A body is a file when its schema is a string of a [FILE_FORMATS] format, whatever label it is
     * declared under, and otherwise when the label is not one the runtime client reads as text
     * ([Rapid7Client.isTextual], so the two cannot disagree). downloadReport declares its report,
     * which its own description says is usually GZip, as `application/json;charset=UTF-8` with
     * `{type: string, format: byte}`. Catalogued by the label alone, the gzip was decoded as UTF-8
     * into the conversation. A file keeps its declared label verbatim: the runtime accepts any type
     * for it and keeps its success body as bytes, so the label only records what the spec said.
     */
    private fun successContentType(op: JsonObject, inliner: Inliner): CatalogResponses {
        val responses = op["responses"] as? JsonObject ?: return CatalogResponses("none", false)
        for (code in responses.keys.sorted()) {
            if (!code.startsWith("2")) continue
            val content = responses[code]?.jsonObject?.get("content") as? JsonObject
            if (content.isNullOrEmpty()) return CatalogResponses("none", false)
            val ct = content.keys.first()
            val schema = inliner.deref((content[ct] as? JsonObject)?.get("schema"))
            if (isFileSchema(schema) || !isTextualLabel(ct, op)) return CatalogResponses(ct, true)
            return when {
                "json" in ct -> CatalogResponses("application/json", false)
                ct.startsWith("text/html") -> CatalogResponses("text/html", false)
                ct.startsWith("text/plain") -> CatalogResponses("text/plain", false)
                else -> CatalogResponses(ct, false)
            }
        }
        return CatalogResponses("none", false)
    }

    /** Whether [schema] is a file: a string of raw (`binary`) or base64-encoded (`byte`) octets. */
    private fun isFileSchema(schema: JsonObject?): Boolean =
        schema != null && (schema["type"] as? JsonPrimitive)?.contentOrNull == "string" &&
            (schema["format"] as? JsonPrimitive)?.contentOrNull in FILE_FORMATS

    private fun isTextualLabel(ct: String, op: JsonObject): Boolean =
        try {
            Rapid7Client.isTextual(ContentType.parse(ct))
        } catch (e: BadContentTypeFormatException) {
            throw CatalogGenerationException("malformed response content type in ${op["operationId"]}: ${e.message}")
        }

    // ------------------------------------------------------------------ catalog

    /** The search-criteria reference in [spec]'s introduction, or null when it has none (v4). */
    fun searchCriteria(spec: JsonObject, specSha256: String, source: String): SearchCriteriaReference? =
        SearchCriteriaTables.parse(introduction(spec), SearchCriteriaMeta(specSha256, GENERATOR_VERSION, source))

    private fun introduction(spec: JsonObject): String? = ((spec["info"] as? JsonObject)?.get("description") as? JsonPrimitive)?.contentOrNull

    /**
     * An operation's cleaned description, capped. One that is a copy of the search-criteria tables
     * ([CRITERIA_TABLE_OPS]) keeps its first sentence and points at the reference tool instead. Any
     * other that the cap would cut by more than [MAX_DESCRIPTION_CUT] fails generation unless it is
     * in [LONG_DESCRIPTION_OPS].
     */
    private fun describe(op: JsonObject, method: String, path: String): String {
        val full = cleanText(op["description"]?.jsonPrimitive?.contentOrNull, Int.MAX_VALUE)
        if ((method to path) in CRITERIA_TABLE_OPS) return "${FIRST_SENTENCE.find(full)?.value ?: full} $ASSET_CRITERIA_POINTER".trim()
        // cap keeps MAX_DESCRIPTION - 1 characters and an ellipsis.
        val lost = full.length - (MAX_DESCRIPTION - 1)
        if (lost > MAX_DESCRIPTION_CUT && (method to path) !in LONG_DESCRIPTION_OPS) {
            throw CatalogGenerationException(
                "the description of ${op["operationId"]} is ${full.length} characters, and the $MAX_DESCRIPTION-character cap would drop " +
                    "$lost of them; shorten it in the generator or allow-list it in LONG_DESCRIPTION_OPS",
            )
        }
        return cap(full, MAX_DESCRIPTION)
    }

    /** [body] with [note] after its own description. */
    private fun withNote(body: CatalogBody, note: String): CatalogBody {
        val own = (body.schema["description"] as? JsonPrimitive)?.contentOrNull
        return body.copy(schema = JsonObject(body.schema + ("description" to JsonPrimitive(listOfNotNull(own, note).joinToString(" ")))))
    }

    /**
     * Build the catalog for [spec]. [criteria] defaults to the reference in the spec's own
     * introduction; [generate] passes the one it has already parsed, so it is read once.
     */
    fun buildCatalog(
        family: ApiFamily,
        spec: JsonObject,
        specSha256: String,
        source: String,
        criteria: SearchCriteriaReference? = searchCriteria(spec, specSha256, source),
    ): Catalog {
        val components = spec["components"] as? JsonObject
        val inliner = Inliner(components, PROPERTY_OVERRIDES + criteriaOverrides(components, criteria))
        val searchNote = SearchCriteriaTables.section(introduction(spec), "Search Criteria", level = 2)
            ?.let { cleanText(it, MAX_SEARCH_NOTE) }
            ?.takeIf { it.isNotEmpty() }
        val ops = mutableListOf<CatalogOp>()
        for ((path, item) in spec["paths"]!!.jsonObject) {
            val pathItem = item.jsonObject
            if ("parameters" in pathItem) throw CatalogGenerationException("path-level parameters not supported ($path)")
            for (method in HTTP_METHODS) {
                val op = pathItem[method] as? JsonObject ?: continue
                val opId = op["operationId"]?.jsonPrimitive?.contentOrNull
                    ?: throw CatalogGenerationException("missing operationId for ${method.uppercase()} $path")
                val upper = method.uppercase()
                val readOnly = CatalogLoader.isRead(upper, path)
                val admin = (upper to path) in ADMIN_OPS
                ops += CatalogOp(
                    name = family.toolPrefix + snakeCase(opId),
                    opId = opId,
                    method = upper,
                    path = path,
                    tag = (op["tags"] as? JsonArray)?.firstOrNull()?.jsonPrimitive?.content ?: "Untagged",
                    summary = cleanText(op["summary"]?.jsonPrimitive?.contentOrNull, MAX_SUMMARY),
                    description = describe(op, upper, path),
                    readOnly = readOnly,
                    // A DELETE and the console command are destructive whatever their id says.
                    destructive = !readOnly && (upper == "DELETE" || admin || !ADDITIVE_OPID.containsMatchIn(opId)),
                    admin = admin,
                    sensitive = CatalogLoader.isSensitive(upper, path),
                    params = buildParams(op, inliner, family),
                    body = buildBody(op, upper, path, inliner)?.let { body ->
                        if (searchNote != null && (upper to path) in SEARCH_NOTE_OPS) withNote(body, searchNote) else body
                    },
                    responses = successContentType(op, inliner),
                )
            }
        }
        ops.sortWith(compareBy({ it.path }, { it.method }))
        val info = spec["info"] as? JsonObject
        val meta = CatalogMeta(
            family = family.id,
            title = info?.get("title")?.jsonPrimitive?.contentOrNull ?: "",
            specVersion = info?.get("version")?.jsonPrimitive?.contentOrNull ?: "",
            specSha256 = specSha256,
            generator = GENERATOR_VERSION,
            generatedFrom = source,
            opCount = ops.size,
        )
        return Catalog(meta, ops)
    }

    /** Every file [generate] writes: one catalog per source, then the search-criteria reference. */
    val OUTPUTS: List<String> get() = SOURCES.map { it.outputFile } + SEARCH_CRITERIA_FILE

    /**
     * Generate every catalog, and the console's search-criteria reference, from [specDir]; validates
     * with the runtime loaders' own invariants. The console specification must carry the reference:
     * the tool that serves it is registered whenever console tools are. The specifications must also
     * still have every route in [CatalogLoader.SENSITIVE_OPS]: the secret gate is keyed by route, so
     * a route the vendor renamed would otherwise be published as an ordinary tool, with no error.
     */
    fun generate(specDir: Path): Map<String, String> {
        val result = LinkedHashMap<String, String>()
        val allNames = HashMap<String, String>()
        val allRoutes = HashSet<Pair<String, String>>()
        var reference: SearchCriteriaReference? = null
        for (src in SOURCES) {
            val raw = Files.readAllBytes(specDir.resolve(src.specFile))
            val sha = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
            val spec = Json.parseToJsonElement(raw.toString(Charsets.UTF_8)).jsonObject
            val source = "specs/${src.specFile}"
            val criteria = searchCriteria(spec, sha, source)
            if (src.family == ApiFamily.CONSOLE) reference = criteria
            val catalog = buildCatalog(src.family, spec, sha, source, criteria)
            CatalogLoader.validate(catalog, src.family)
            for (op in catalog.ops) {
                allNames.put(op.name, src.family.id)?.let { throw CatalogGenerationException("duplicate tool name ${op.name} ($it and ${src.family.id})") }
                allRoutes += op.method to op.path
            }
            result[src.outputFile] = output.encodeToString(Catalog.serializer(), catalog) + "\n"
        }
        val console = SOURCES.first { it.family == ApiFamily.CONSOLE }.specFile
        val found = reference ?: throw CatalogGenerationException("specs/$console has no search-criteria reference ('Fields' table) in its introduction")
        val lost = CatalogLoader.SENSITIVE_OPS - allRoutes
        if (lost.isNotEmpty()) {
            throw CatalogGenerationException(
                "the specifications no longer have ${lost.joinToString { (method, path) -> "$method $path" }}, which " +
                    "CatalogLoader.SENSITIVE_OPS gates as returning or setting a secret; find the renamed route and update the list",
            )
        }
        result[SEARCH_CRITERIA_FILE] = output.encodeToString(SearchCriteriaReference.serializer(), found) + "\n"
        return result
    }

    /** Write the catalogs to [outDir]. Returns the files written. */
    fun write(specDir: Path, outDir: Path): List<Path> {
        Files.createDirectories(outDir)
        return generate(specDir).map { (name, text) ->
            val target = outDir.resolve(name)
            Files.write(target, text.toByteArray(Charsets.UTF_8))
            target
        }
    }

    /** Names of catalog files in [outDir] that differ from a fresh generation (empty = up to date). */
    fun drift(specDir: Path, outDir: Path): List<String> =
        generate(specDir).filter { (name, text) ->
            val target = outDir.resolve(name)
            !Files.exists(target) || Files.readAllBytes(target).toString(Charsets.UTF_8) != text
        }.keys.toList()

    /**
     * CLI: `CatalogGenerator [--check] [--specs DIR] [--out DIR]`. Defaults are relative to the
     * working directory (`specs/`, `src/main/resources/catalog/`).
     */
    @JvmStatic
    fun main(args: Array<String>) {
        var check = false
        var specs = Path.of("specs")
        var out = Path.of("src/main/resources/catalog")
        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--check" -> check = true
                "--specs" -> specs = Path.of(args[++i])
                "--out" -> out = Path.of(args[++i])
                else -> { System.err.println("unknown argument ${args[i]}"); exitProcess(2) }
            }
            i++
        }
        try {
            if (check) {
                val stale = drift(specs, out)
                if (stale.isNotEmpty()) {
                    System.err.println("catalog out of date: ${stale.joinToString(", ")} - run: ./gradlew generateCatalog")
                    exitProcess(1)
                }
                println("catalog up to date (${OUTPUTS.joinToString(", ")})")
            } else {
                write(specs, out).forEach { println("wrote $it (${Files.size(it)} bytes)") }
            }
        } catch (e: CatalogGenerationException) {
            System.err.println("catalog generation failed: ${e.message}")
            exitProcess(1)
        }
    }
}
