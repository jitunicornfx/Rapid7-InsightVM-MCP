package com.jitunicornfx.insightvm.mcp.catalog

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
 * Generates the tool catalog (`src/main/resources/catalog/{v3,v4}.json`) from the bundled OpenAPI
 * documents in `specs/`. The runtime registers one tool per catalog entry and never parses the raw
 * specifications; output is deterministic so `--check` can detect drift.
 *
 * Run through Gradle: `./gradlew generateCatalog` (regenerate) / `./gradlew verifyCatalog` (drift
 * check, part of `check`). The rules below are documented in `tools/README.md`.
 */
object CatalogGenerator {

    const val GENERATOR_VERSION = "CatalogGenerator.kt@1"
    const val MAX_DESCRIPTION = 600
    const val MAX_PROPERTY_DESCRIPTION = 400
    const val MAX_SUMMARY = 120
    const val MAX_DEPTH = 8

    private val HTTP_METHODS = listOf("get", "post", "put", "delete", "patch")
    private val DESTRUCTIVE_OPID = Regex("^(delete|remove|stop)", RegexOption.IGNORE_CASE)
    private val ADMIN_OPS = setOf("POST" to "/api/3/administration/commands")
    private val STRIP_KEYS = setOf("example", "examples", "xml", "title", "deprecated", "discriminator", "externalDocs")

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

    private val TAG = Regex("<[^>]+>")
    private val WS = Regex("\\s+")
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

    /** Strip HTML, decode entities, collapse whitespace, drop control chars, neutralise `<>`, cap length. */
    internal fun cleanText(text: String?, limit: Int = MAX_DESCRIPTION): String {
        if (text.isNullOrEmpty()) return ""
        var s = TAG.replace(text, " ")
        s = unescapeEntities(s)
        s = CONTROL.replace(s, "")
        s = WS.replace(s, " ").trim()
        s = s.replace("<", "‹").replace(">", "›")
        if (s.length > limit) s = s.substring(0, limit - 1).trimEnd() + "…"
        return s
    }

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

    private class Inliner(components: JsonObject?) {
        private val schemas: JsonObject = components?.get("schemas")?.jsonObject ?: JsonObject(emptyMap())

        private fun resolve(ref: String): Pair<String, JsonObject> {
            val prefix = "#/components/schemas/"
            if (!ref.startsWith(prefix)) throw CatalogGenerationException("unsupported \$ref: $ref")
            val name = ref.removePrefix(prefix)
            val target = schemas[name] as? JsonObject ?: throw CatalogGenerationException("unknown schema: $name")
            return name to target
        }

        fun inline(schema: JsonElement?, depth: Int = 0, stack: List<String> = emptyList()): JsonElement? {
            if (schema !is JsonObject) return schema
            schema["\$ref"]?.let { refElement ->
                val (name, target) = resolve(refElement.jsonPrimitive.content)
                if (name in stack || depth > MAX_DEPTH) {
                    return JsonObject(
                        mapOf(
                            "type" to JsonPrimitive("object"),
                            "description" to JsonPrimitive("$name (nested object; see the Rapid7 API documentation)"),
                        ),
                    )
                }
                val merged = inline(target, depth + 1, stack + name)
                val extra = schema["description"]
                return if (merged is JsonObject && extra != null) JsonObject(merged + ("description" to extra)) else merged
            }

            val out = LinkedHashMap<String, JsonElement>()
            for ((key, value) in schema) {
                when {
                    key in STRIP_KEYS -> Unit
                    key == "properties" && value is JsonObject -> {
                        val props = LinkedHashMap<String, JsonElement>()
                        for ((pname, pschema) in value) {
                            if (pschema is JsonObject && pschema["readOnly"]?.jsonPrimitive?.booleanOrNull == true) continue
                            props[pname] = inline(pschema, depth + 1, stack) ?: pschema
                        }
                        out["properties"] = JsonObject(props)
                    }
                    key == "items" -> out["items"] = inline(value, depth + 1, stack) ?: value
                    key == "additionalProperties" -> out["additionalProperties"] = if (value is JsonObject) inline(value, depth + 1, stack) ?: value else value
                    (key == "allOf" || key == "oneOf" || key == "anyOf") && value is JsonArray ->
                        out[key] = JsonArray(value.map { inline(it, depth + 1, stack) ?: it })
                    key == "description" -> out["description"] = JsonPrimitive(cleanText(value.jsonPrimitive.contentOrNull, MAX_PROPERTY_DESCRIPTION))
                    key == "readOnly" -> Unit
                    else -> out[key] = value
                }
            }
            val required = out["required"]
            if (out["properties"] is JsonObject && required is JsonArray) {
                val props = out["properties"]!!.jsonObject
                val kept = required.filter { it.jsonPrimitive.content in props }
                if (kept.isEmpty()) out.remove("required") else out["required"] = JsonArray(kept)
            }
            return JsonObject(out)
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
        return JsonObject(schema) to isArray
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
            val (schemaBase, isArray) = normalizeParamSchema(param["schema"], inliner)
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

    private fun buildBody(op: JsonObject, inliner: Inliner): CatalogBody? {
        val rb = op["requestBody"] as? JsonObject ?: return null
        val content = rb["content"] as? JsonObject ?: JsonObject(emptyMap())
        val required = rb["required"]?.jsonPrimitive?.booleanOrNull == true
        content["application/json"]?.let { json ->
            val inlined = inliner.inline(json.jsonObject["schema"] ?: JsonObject(emptyMap())) as? JsonObject
            val schema = LinkedHashMap(inlined?.takeIf { it.isNotEmpty() } ?: JsonObject(mapOf("type" to JsonPrimitive("object"))))
            if ("type" !in schema) schema["type"] = JsonPrimitive("object")
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

    private fun successContentType(op: JsonObject): CatalogResponses {
        val responses = op["responses"] as? JsonObject ?: return CatalogResponses("none", false)
        for (code in responses.keys.sorted()) {
            if (!code.startsWith("2")) continue
            val content = responses[code]?.jsonObject?.get("content") as? JsonObject
            if (content.isNullOrEmpty()) return CatalogResponses("none", false)
            val ct = content.keys.first()
            return when {
                "json" in ct -> CatalogResponses("application/json", false)
                ct.startsWith("text/html") -> CatalogResponses("text/html", false)
                ct.startsWith("text/plain") -> CatalogResponses("text/plain", false)
                else -> CatalogResponses(ct, true)
            }
        }
        return CatalogResponses("none", false)
    }

    // ------------------------------------------------------------------ catalog

    fun buildCatalog(family: ApiFamily, spec: JsonObject, specSha256: String, source: String): Catalog {
        val inliner = Inliner(spec["components"] as? JsonObject)
        val ops = mutableListOf<CatalogOp>()
        for ((path, item) in spec["paths"]!!.jsonObject) {
            val pathItem = item.jsonObject
            if ("parameters" in pathItem) throw CatalogGenerationException("path-level parameters not supported ($path)")
            for (method in HTTP_METHODS) {
                val op = pathItem[method] as? JsonObject ?: continue
                val opId = op["operationId"]?.jsonPrimitive?.contentOrNull
                    ?: throw CatalogGenerationException("missing operationId for ${method.uppercase()} $path")
                val upper = method.uppercase()
                ops += CatalogOp(
                    name = family.toolPrefix + snakeCase(opId),
                    opId = opId,
                    method = upper,
                    path = path,
                    tag = (op["tags"] as? JsonArray)?.firstOrNull()?.jsonPrimitive?.content ?: "Untagged",
                    summary = cleanText(op["summary"]?.jsonPrimitive?.contentOrNull, MAX_SUMMARY),
                    description = cleanText(op["description"]?.jsonPrimitive?.contentOrNull),
                    readOnly = upper == "GET",
                    destructive = upper == "DELETE" || DESTRUCTIVE_OPID.containsMatchIn(opId),
                    admin = (upper to path) in ADMIN_OPS,
                    params = buildParams(op, inliner, family),
                    body = buildBody(op, inliner),
                    responses = successContentType(op),
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

    /** Generate every catalog from [specDir]; validates with the runtime loader's own invariants. */
    fun generate(specDir: Path): Map<String, String> {
        val result = LinkedHashMap<String, String>()
        val allNames = HashMap<String, String>()
        for (src in SOURCES) {
            val raw = Files.readAllBytes(specDir.resolve(src.specFile))
            val sha = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
            val spec = Json.parseToJsonElement(raw.toString(Charsets.UTF_8)).jsonObject
            val catalog = buildCatalog(src.family, spec, sha, "specs/${src.specFile}")
            CatalogLoader.validate(catalog, src.family)
            for (op in catalog.ops) {
                allNames.put(op.name, src.family.id)?.let { throw CatalogGenerationException("duplicate tool name ${op.name} ($it and ${src.family.id})") }
            }
            result[src.outputFile] = output.encodeToString(Catalog.serializer(), catalog) + "\n"
        }
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
                println("catalog up to date (${SOURCES.joinToString(", ") { it.outputFile }})")
            } else {
                write(specs, out).forEach { println("wrote $it (${Files.size(it)} bytes)") }
            }
        } catch (e: CatalogGenerationException) {
            System.err.println("catalog generation failed: ${e.message}")
            exitProcess(1)
        }
    }
}
