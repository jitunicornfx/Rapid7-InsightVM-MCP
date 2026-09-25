package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.catalog.CatalogGenerator.CatalogGenerationException

/**
 * Build-time extraction of the [SearchCriteriaReference] from the v3 specification's introduction
 * (`info.description`). The console documents search criteria there in markdown tables, under
 * "Search Criteria" and "Discovery Connection Search Criteria", and nowhere else: the filter schemas
 * only link to that section, which a model cannot follow.
 *
 * The tables are read strictly. An unexpected column, a cell with text outside its backticks, an
 * invalid name, or an operator no field uses fails generation, so a changed table is looked at
 * rather than half-read.
 */
internal object SearchCriteriaTables {

    /**
     * The Operator Properties table names four operators differently from the field tables that use
     * them (`ends with` for `ends-with`, and so on). Each is mapped here, explicitly; any other name
     * that no field table uses fails generation.
     */
    val OPERATOR_ALIASES = mapOf(
        "ends with" to "ends-with",
        "less-than" to "is-less-than",
        "like" to "is-like",
        "not-contains" to "does-not-contain",
    )

    /** A markdown heading. The v3 introduction appends an empty `<a section="…"></a>` anchor to some. */
    private val HEADING = Regex("(#{1,6})\\s+(.*?)\\s*(?:<a\\b[^>]*>\\s*</a>)?")
    private val FENCE = Regex("^\\s*```")
    private val SEPARATOR = Regex("\\|(\\s*:?-{3,}:?\\s*\\|)+")
    private val CODE = Regex("`([^`]*)`")
    private val LIST_ITEM = Regex("<li>(.*?)</li>", RegexOption.IGNORE_CASE)
    private val EQUALS = Regex("\\s*=\\s*")
    private val BRACKETED = Regex("\\[\\s*(.*?)\\s*]")
    private val NAME = Regex("[A-Za-z0-9]+(-[A-Za-z0-9]+)*")
    private val DISCOVERY_FIELDS = Regex("Fields \\((.+)\\)")
    private val DISCOVERY_VALUES = Regex("Enumerated Properties \\((.+)\\)")

    /** How the introduction names a discovery connection type: `"aws"`, quoted inside backticks. */
    private val CONNECTION_TYPE = Regex("`\"([a-z0-9-]+)\"`")

    class Section(val level: Int, val title: String, val body: String)

    private fun fail(what: String) = CatalogGenerationException("search-criteria reference: $what")

    /** [text] split at its markdown headings. A `#` line inside a fenced code block is not a heading. */
    fun sections(text: String): List<Section> {
        val out = mutableListOf<Section>()
        var heading: MatchResult? = null
        val body = StringBuilder()
        var fenced = false
        fun close() {
            heading?.let { out += Section(it.groupValues[1].length, it.groupValues[2], body.toString()) }
            body.setLength(0)
        }
        for (line in text.lines()) {
            if (FENCE.containsMatchIn(line)) fenced = !fenced
            val match = if (fenced) null else HEADING.matchEntire(line.trimEnd())
            if (match == null) body.append(line).append('\n') else { close(); heading = match }
        }
        close()
        return out
    }

    /** The body of the section of [text] titled [title], at heading [level] when one is given; null when there is none. */
    fun section(text: String?, title: String, level: Int? = null): String? = one(sections(text ?: return null), title, level)

    private fun one(all: List<Section>, title: String, level: Int? = null): String? {
        val found = all.filter { it.title == title && (level == null || it.level == level) }
        if (found.size > 1) throw fail("${found.size} sections are titled '$title'")
        return found.singleOrNull()?.body
    }

    /**
     * The reference in [info], or null when it has no asset "Fields" table (the v4 specification, and
     * the small specifications the tests build). Once that table is there, the enumerated-values and
     * operator tables and at least one discovery table must be too.
     */
    fun parse(info: String?, meta: SearchCriteriaMeta): SearchCriteriaReference? {
        val all = sections(info ?: return null)
        val asset = fields(one(all, "Fields") ?: return null, "Fields")
        val assetValues = values(one(all, "Enumerated Properties") ?: throw fail("no 'Enumerated Properties' section"), "Enumerated Properties")

        val discovery = all.mapNotNull { s -> DISCOVERY_FIELDS.matchEntire(s.title)?.let { connection(it.groupValues[1], s.body) } }
        if (discovery.isEmpty()) throw fail("no discovery 'Fields (…)' section")
        if (discovery.map { it.name }.toSet().size != discovery.size) throw fail("a discovery connection has two 'Fields (…)' sections")
        val discoveryValues = LinkedHashMap<String, Map<String, List<String>>>()
        for (s in all) {
            val name = DISCOVERY_VALUES.matchEntire(s.title)?.groupValues?.get(1) ?: continue
            if (discovery.none { it.name == name }) throw fail("'${s.title}' names no discovery connection with a fields table")
            if (discoveryValues.put(name, values(s.body, s.title)) != null) throw fail("two '${s.title}' sections")
        }

        val used = (asset + discovery.flatMap { it.fields }).flatMap { it.operators }.toSet()
        val operators = operators(one(all, "Operator Properties") ?: throw fail("no 'Operator Properties' section"), used)
        return SearchCriteriaReference(
            meta = meta,
            operators = operators,
            asset = withValues(asset, assetValues, "Enumerated Properties"),
            discovery = discovery.map { c ->
                c.copy(fields = withValues(c.fields, discoveryValues[c.name].orEmpty(), "Enumerated Properties (${c.name})"))
            },
        ).also { SearchCriteria.validate(it) }
    }

    /** The data rows of the first markdown table in [body], checked against [header], as trimmed cells. */
    private fun table(body: String, what: String, header: List<String>): List<List<String>> {
        fun cells(line: String) = line.removePrefix("|").removeSuffix("|").split('|').map { it.trim() }
        val lines = body.lines().map { it.trim() }.dropWhile { !it.startsWith("|") }.takeWhile { it.startsWith("|") }
        if (lines.size < 3 || !SEPARATOR.matches(lines[1])) throw fail("'$what' has no markdown table")
        val columns = cells(lines[0]).map { it.replace("`", "") }
        if (columns.map { it.lowercase() } != header.map { it.lowercase() }) throw fail("'$what' has columns $columns, not $header")
        return lines.drop(2).map { line ->
            cells(line).also { if (it.size != header.size) throw fail("'$what' has a row of ${it.size} cells: $line") }
        }
    }

    /** The backticked tokens in [cell], trimmed: the spec has stray spaces such as `` ` in-range` ``. */
    private fun codes(cell: String, what: String): List<String> {
        if (CODE.replace(cell, "").isNotBlank()) throw fail("'$what' has text outside backticks: $cell")
        return CODE.findAll(cell).map { it.groupValues[1].trim() }.toList().ifEmpty { throw fail("'$what' has an empty cell") }
    }

    /** [codes] that must each be a valid, distinct name. */
    private fun names(cell: String, what: String): List<String> {
        val names = codes(cell, what)
        names.firstOrNull { !NAME.matches(it) }?.let { throw fail("'$what' has an invalid name '$it'") }
        if (names.toSet().size != names.size) throw fail("'$what' repeats a name: $cell")
        return names
    }

    private fun single(cell: String, what: String): String =
        names(cell, what).singleOrNull() ?: throw fail("'$what' has a row naming more than one field: $cell")

    private fun fields(body: String, what: String): List<CriteriaField> {
        val seen = HashSet<String>()
        return table(body, what, listOf("Field", "Operators")).map { (field, operators) ->
            val name = single(field, what)
            if (!seen.add(name)) throw fail("'$what' lists $name twice")
            CriteriaField(name, names(operators, "$what: $name"))
        }
    }

    private fun connection(name: String, body: String): DiscoveryConnection {
        val types = CONNECTION_TYPE.findAll(body).map { it.groupValues[1] }.distinct().toList()
        if (types.isEmpty()) throw fail("'Fields ($name)' names no connection type")
        return DiscoveryConnection(name, types, fields(body, "Fields ($name)"))
    }

    /**
     * Field → its acceptable values. The table writes them three ways: `0=IPv4, 1=IPv6`, backticked
     * names, and an HTML list of `<code>L</code> = Low` items. All three become `name=meaning` or a
     * bare name.
     */
    private fun values(body: String, what: String): Map<String, List<String>> {
        val out = LinkedHashMap<String, List<String>>()
        for ((field, cell) in table(body, what, listOf("Field", "Acceptable Values"))) {
            val items = when {
                LIST_ITEM.containsMatchIn(cell) -> LIST_ITEM.findAll(cell).map { it.groupValues[1] }.toList()
                CODE.containsMatchIn(cell) -> codes(cell, what)
                else -> cell.split(',')
            }.map { EQUALS.replace(CatalogGenerator.cleanText(it), "=") }
            if (items.isEmpty() || items.any { it.isEmpty() }) throw fail("'$what' has an empty value: $cell")
            if (out.put(single(field, what), items) != null) throw fail("'$what' lists $field twice")
        }
        return out
    }

    private fun withValues(fields: List<CriteriaField>, values: Map<String, List<String>>, what: String): List<CriteriaField> {
        values.keys.firstOrNull { name -> fields.none { it.name == name } }?.let { throw fail("'$what' lists values for '$it', which no fields table has") }
        return fields.map { f -> values[f.name]?.let { f.copy(values = it) } ?: f }
    }

    /**
     * Operator → the properties it reads → their types as written (`numeric (days)`). Names go
     * through [OPERATOR_ALIASES]; a name that is still not one a field uses fails. A name listed twice
     * (`does-not-contain` also appears as `not-contains`) must read the same properties both times.
     */
    private fun operators(body: String, used: Set<String>): Map<String, Map<String, String>> {
        val what = "Operator Properties"
        val out = LinkedHashMap<String, Map<String, String>>()
        for (row in table(body, what, listOf("Operator") + SearchCriteria.VALUE_PROPERTIES)) {
            val raw = codes(row[0], what).singleOrNull() ?: throw fail("'$what' has a row naming more than one operator: ${row[0]}")
            val name = OPERATOR_ALIASES[raw] ?: raw
            if (name !in used) throw fail("'$what' names '$raw', which no field table uses and no alias maps")
            val reads = LinkedHashMap<String, String>()
            SearchCriteria.VALUE_PROPERTIES.forEachIndexed { i, property ->
                val type = BRACKETED.replace(CatalogGenerator.cleanText(row[i + 1].replace("`", "")), "[$1]")
                if (type.isNotEmpty()) reads[property] = type
            }
            val previous = out.putIfAbsent(name, reads)
            if (previous != null && previous != reads) throw fail("'$what' gives $name two different sets of properties")
        }
        return out
    }
}
