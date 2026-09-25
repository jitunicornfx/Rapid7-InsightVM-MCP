package com.jitunicornfx.insightvm.mcp.catalog

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The Security Console's search-criteria reference: the fields a filter can name, the operators each
 * field accepts, the values an enumerated field takes, and the properties (`value`, `lower`, `upper`)
 * each operator reads. The console documents it only in its specification's introduction, which no
 * operation or schema carries, so the filter schemas said "See Search Criteria" and nothing more.
 * [CatalogGenerator] extracts the tables into `catalog/search-criteria.json`, and the
 * [CatalogTools.SEARCH_CRITERIA_TOOL] tool serves them.
 *
 * Every string comes from the bundled specification through the generator's text cleaning, so the
 * tool built on it returns server-authored text, never anything the API sent.
 */
@Serializable
data class SearchCriteriaReference(
    val meta: SearchCriteriaMeta,
    /** Operator → the properties it reads → the type the specification gives each. Empty for an operator that takes no value. */
    val operators: Map<String, Map<String, String>>,
    /** Asset search criteria: find_assets, and the `searchCriteria` of asset groups and tags. */
    val asset: List<CriteriaField>,
    /** A dynamic site's discovery search criteria, whose fields depend on the discovery connection type. */
    val discovery: List<DiscoveryConnection>,
)

@Serializable
data class SearchCriteriaMeta(
    val specSha256: String = "",
    val generator: String = "",
    val generatedFrom: String = "",
)

/** One filterable field, the operators it accepts in the specification's order, and its values when it is enumerated. */
@Serializable
data class CriteriaField(
    val name: String,
    val operators: List<String>,
    val values: List<String> = emptyList(),
)

/** The fields one kind of discovery connection supports; [connectionTypes] are the `connectionType` values it covers. */
@Serializable
data class DiscoveryConnection(
    val name: String,
    val connectionTypes: List<String>,
    val fields: List<CriteriaField>,
)

/** Loads the bundled [SearchCriteriaReference] and renders it for the model. */
object SearchCriteria {

    const val RESOURCE = "/catalog/search-criteria.json"

    /** Which criteria a lookup covers, by the `kind` argument's value. */
    enum class Kind(val id: String) {
        ASSET("asset"),
        DISCOVERY("discovery");

        companion object {
            fun fromId(value: String): Kind =
                entries.firstOrNull { it.id == value.trim().lowercase() }
                    ?: throw IllegalArgumentException("'kind' must be one of: ${entries.joinToString { it.id }}.")
        }
    }

    /** The filter properties an operator can read, in the order the console documents them. */
    val VALUE_PROPERTIES = listOf("value", "lower", "upper")

    private val json = Json { ignoreUnknownKeys = true }

    /** Field names, operator names and connection types; anything else is not a name the console defines. */
    private val NAME = Regex("^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$")

    /** Where HTML could open markup, as [CatalogLoader] checks a tool description. */
    private val MARKUP = Regex("<[A-Za-z/!?]")

    /** Parsed once: every server built in this process serves the same bundled reference. */
    val bundled: SearchCriteriaReference by lazy { load() }

    fun load(): SearchCriteriaReference {
        val stream = SearchCriteria::class.java.getResourceAsStream(RESOURCE)
            ?: throw IllegalStateException("Search-criteria reference $RESOURCE is missing from the classpath.")
        return parse(stream.use { it.readBytes().toString(Charsets.UTF_8) })
    }

    /** Parse and validate reference JSON; throws [IllegalStateException] on any invariant violation. */
    fun parse(text: String): SearchCriteriaReference {
        val reference = try {
            json.decodeFromString(SearchCriteriaReference.serializer(), text)
        } catch (e: Exception) {
            throw IllegalStateException("Search-criteria reference is not valid: ${e.message}", e)
        }
        validate(reference)
        return reference
    }

    internal fun validate(reference: SearchCriteriaReference) {
        check(reference.asset.isNotEmpty()) { "Search-criteria reference lists no asset field" }
        check(reference.discovery.isNotEmpty() && reference.discovery.all { it.fields.isNotEmpty() && it.connectionTypes.isNotEmpty() }) {
            "Search-criteria reference lists a discovery connection with no field or no connection type"
        }
        val fields = reference.asset + reference.discovery.flatMap { it.fields }
        val names = fields.flatMap { listOf(it.name) + it.operators } + reference.operators.keys +
            reference.discovery.flatMap { it.connectionTypes }
        names.firstOrNull { !NAME.matches(it) }?.let { throw IllegalStateException("Search-criteria reference has an invalid name '$it'") }
        check(fields.all { it.operators.isNotEmpty() }) { "Search-criteria reference lists a field with no operator" }
        check(reference.operators.values.all { it.keys.all { p -> p in VALUE_PROPERTIES } }) {
            "Search-criteria reference names an operator property other than ${VALUE_PROPERTIES.joinToString()}"
        }
        val text = fields.flatMap { it.values } + reference.discovery.map { it.name } + reference.operators.values.flatMap { it.values }
        check(text.none { MARKUP.containsMatchIn(it) }) { "Search-criteria reference contains markup" }
    }

    private const val FILTER_SHAPE =
        "A filter is {\"field\": ..., \"operator\": ...} plus the properties its operator reads; \"match\" is \"all\" or \"any\"."

    /**
     * The reference for [kind] as plain text, narrowed to one [field] (case-insensitive) when given.
     * Null when no field of that kind has that name. Operators are listed once, after the fields,
     * with the property types exactly as the specification gives them.
     */
    fun render(reference: SearchCriteriaReference, kind: Kind, field: String?): String? {
        val wanted = field?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        fun matches(f: CriteriaField) = wanted == null || f.name.lowercase() == wanted
        return when (kind) {
            Kind.ASSET -> {
                val fields = reference.asset.filter(::matches).ifEmpty { return null }
                buildString {
                    append("Asset search criteria: the filters of find_assets and of the searchCriteria of asset groups and tags. ")
                    append(FILTER_SHAPE).append("\n\nFields and the operators each accepts:\n")
                    fields.forEach { append(line(it)) }
                    append(operators(reference, fields))
                }
            }
            Kind.DISCOVERY -> {
                val connections = reference.discovery.mapNotNull { c -> c.fields.filter(::matches).takeIf { it.isNotEmpty() }?.let { c to it } }
                if (connections.isEmpty()) return null
                buildString {
                    append("Discovery search criteria: the filters of a dynamic site's discovery search criteria. The fields a filter ")
                    append("can name depend on the site's discovery connection type (connectionType). ").append(FILTER_SHAPE)
                    for ((connection, fields) in connections) {
                        append("\n\n${connection.name} (connectionType ${connection.connectionTypes.joinToString(", ")}):\n")
                        fields.forEach { append(line(it)) }
                    }
                    append(operators(reference, connections.flatMap { it.second }))
                }
            }
        }
    }

    private fun line(field: CriteriaField): String =
        "- ${field.name}: ${field.operators.joinToString(", ")}" +
            (if (field.values.isEmpty()) "" else ". Values: ${field.values.joinToString(", ")}") + "\n"

    /** The operators [fields] use, in order of first use, each with the properties it reads. */
    private fun operators(reference: SearchCriteriaReference, fields: List<CriteriaField>): String = buildString {
        append("\nOperators and the properties each reads:\n")
        for (operator in fields.flatMap { it.operators }.distinct()) {
            val reads = reference.operators[operator]
            val what = when {
                reads == null -> "not documented in the specification"
                reads.isEmpty() -> "no value"
                else -> reads.entries.joinToString(", ") { (property, type) -> "$property=$type" }
            }
            append("- $operator: $what\n")
        }
    }.trimEnd()
}
