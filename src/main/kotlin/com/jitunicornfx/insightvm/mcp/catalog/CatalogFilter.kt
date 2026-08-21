package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.ToolFilter

/** Applies a [ToolFilter] to catalogs, deciding which operations become tools. */
object CatalogFilter {

    data class Selection(val family: ApiFamily, val op: CatalogOp)

    /**
     * Select operations from [catalogs] honouring [filter]. Order of the checks: family → admin
     * gate → read-only → tags → excluded tags → name globs. The admin gate always applies: the
     * console command operation is never registered unless [ToolFilter.allowAdminCommands] is set.
     */
    fun select(catalogs: Map<ApiFamily, Catalog>, filter: ToolFilter): List<Selection> {
        val tags = filter.tags.map { it.lowercase() }.toSet()
        val excluded = filter.excludeTags.map { it.lowercase() }.toSet()
        val globs = filter.nameGlobs.map { globToRegex(it) }
        return catalogs.entries
            .filter { (family, _) -> family in filter.families }
            .sortedBy { (family, _) -> family.ordinal }
            .flatMap { (family, catalog) ->
                catalog.ops.asSequence()
                    .filter { op -> !op.admin || filter.allowAdminCommands }
                    .filter { op -> !filter.readOnly || op.readOnly }
                    .filter { op -> tags.isEmpty() || op.tag.lowercase() in tags }
                    .filter { op -> op.tag.lowercase() !in excluded }
                    .filter { op -> globs.isEmpty() || globs.any { it.matches(op.name) } }
                    .map { Selection(family, it) }
                    .toList()
            }
    }

    /** Human-readable one-line summary for the startup log. */
    fun summarize(selected: List<Selection>, catalogs: Map<ApiFamily, Catalog>, filter: ToolFilter): String {
        val total = catalogs.filterKeys { it in filter.families }.values.sumOf { it.ops.size }
        val perFamily = ApiFamily.entries
            .filter { f -> catalogs.containsKey(f) && f in filter.families }
            .joinToString(", ") { f -> "${f.id}=${selected.count { it.family == f }}" }
        val flags = buildList {
            if (filter.readOnly) add("read-only")
            if (filter.tags.isNotEmpty()) add("tags=${filter.tags.joinToString("|")}")
            if (filter.excludeTags.isNotEmpty()) add("exclude-tags=${filter.excludeTags.joinToString("|")}")
            if (filter.nameGlobs.isNotEmpty()) add("tools=${filter.nameGlobs.joinToString("|")}")
            if (filter.allowAdminCommands) add("ADMIN COMMANDS ENABLED")
        }
        return "registered ${selected.size}/$total API tools ($perFamily)" +
            if (flags.isEmpty()) "" else " [${flags.joinToString(", ")}]"
    }

    /** Convert a shell-style glob (`*`, `?`) into an anchored regex; all other characters are literal. */
    internal fun globToRegex(glob: String): Regex {
        val sb = StringBuilder("^")
        for (ch in glob) {
            when (ch) {
                '*' -> sb.append(".*")
                '?' -> sb.append('.')
                else -> sb.append(Regex.escape(ch.toString()))
            }
        }
        return Regex(sb.append('$').toString())
    }
}
