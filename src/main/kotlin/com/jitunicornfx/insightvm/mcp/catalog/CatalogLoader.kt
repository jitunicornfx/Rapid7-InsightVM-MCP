package com.jitunicornfx.insightvm.mcp.catalog

import kotlinx.serialization.json.Json

/** Loads the generated operation catalogs from the classpath and checks their invariants. */
object CatalogLoader {
    private val json = Json { ignoreUnknownKeys = true }

    val TOOL_NAME_PATTERN = Regex("^[a-z0-9_]{1,64}$")
    private val PLACEHOLDER = Regex("\\{([^{}]+)}")

    /**
     * Where HTML could open markup: a `<` followed by a letter, `/`, `!` or `?`. A bare `<` or `>` is
     * text, and the v4 query language needs it (`cvss_score >= 9`), so it is not refused.
     */
    private val MARKUP = Regex("<[A-Za-z/!?]")

    fun load(family: ApiFamily): Catalog {
        val stream = CatalogLoader::class.java.getResourceAsStream(family.resource)
            ?: throw IllegalStateException("Catalog resource ${family.resource} is missing from the classpath.")
        val text = stream.use { it.readBytes().toString(Charsets.UTF_8) }
        return parse(text, family)
    }

    fun loadAll(families: Collection<ApiFamily> = ApiFamily.entries): Map<ApiFamily, Catalog> =
        families.associateWith { load(it) }

    /** Parse and validate catalog JSON for [family]; throws [IllegalStateException] on any invariant violation. */
    fun parse(text: String, family: ApiFamily): Catalog {
        val catalog = try {
            json.decodeFromString(Catalog.serializer(), text)
        } catch (e: Exception) {
            throw IllegalStateException("Catalog for ${family.id} is not valid: ${e.message}", e)
        }
        validate(catalog, family)
        return catalog
    }

    internal fun validate(catalog: Catalog, family: ApiFamily) {
        check(catalog.meta.family == family.id) {
            "Catalog family mismatch: expected ${family.id}, found ${catalog.meta.family}"
        }
        check(catalog.ops.size == catalog.meta.opCount) {
            "Catalog ${family.id}: meta.opCount=${catalog.meta.opCount} but ${catalog.ops.size} operations present"
        }
        val seen = HashSet<String>()
        for (op in catalog.ops) {
            check(TOOL_NAME_PATTERN.matches(op.name)) { "Catalog ${family.id}: invalid tool name '${op.name}'" }
            check(op.name.startsWith(family.toolPrefix)) { "Catalog ${family.id}: '${op.name}' lacks prefix '${family.toolPrefix}'" }
            check(seen.add(op.name)) { "Catalog ${family.id}: duplicate tool name '${op.name}'" }
            check(op.method in METHODS) { "Catalog ${family.id}: '${op.name}' has unsupported method ${op.method}" }
            check(op.path.startsWith("/")) { "Catalog ${family.id}: '${op.name}' path must start with '/'" }
            check(op.readOnly == (op.method == "GET")) { "Catalog ${family.id}: '${op.name}' readOnly flag disagrees with method" }

            val pathParams = op.params.filter { it.isPath }.map { it.name }.toSet()
            val placeholders = PLACEHOLDER.findAll(op.path).map { it.groupValues[1] }.toSet()
            check(pathParams == placeholders) {
                "Catalog ${family.id}: '${op.name}' path parameters $pathParams do not match template placeholders $placeholders"
            }
            val names = HashSet<String>()
            for (p in op.params) {
                check(p.isPath || p.isQuery) { "Catalog ${family.id}: '${op.name}' parameter '${p.name}' has unsupported location '${p.`in`}'" }
                check(p.name !in RESERVED_PROPERTIES) { "Catalog ${family.id}: '${op.name}' uses reserved parameter name '${p.name}'" }
                check(names.add(p.name)) { "Catalog ${family.id}: '${op.name}' duplicate parameter '${p.name}'" }
            }
            for (text in listOf(op.summary, op.description)) {
                check(!MARKUP.containsMatchIn(text)) { "Catalog ${family.id}: '${op.name}' description contains markup" }
            }
            op.body?.let { body ->
                check(body.contentType == "application/json" || body.contentType == "text/plain") {
                    "Catalog ${family.id}: '${op.name}' unsupported body content type ${body.contentType}"
                }
            }
        }
    }

    const val BODY_PROPERTY = "body"
    const val CONFIRM_PROPERTY = "confirm"

    /** Synthetic opt-out added to paged tools; never a real API parameter. */
    const val INCLUDE_LINKS_PROPERTY = "include_links"
    private val METHODS = setOf("GET", "POST", "PUT", "DELETE", "PATCH")

    /** Names this server synthesises onto a tool schema, so a spec parameter can never collide. */
    private val RESERVED_PROPERTIES = setOf(BODY_PROPERTY, CONFIRM_PROPERTY, INCLUDE_LINKS_PROPERTY)
}
