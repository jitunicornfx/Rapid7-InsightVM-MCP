package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.ToolFilter

/** Applies a [ToolFilter] to catalogs, deciding which operations become tools. */
object CatalogFilter {

    data class Selection(val family: ApiFamily, val op: CatalogOp)

    /**
     * Select operations from [catalogs] honouring [filter]. Order of the checks: family → admin
     * gate → secret gate → read-only → tags → excluded tags → name globs. Both gates always apply:
     * the console command operation is never registered unless [ToolFilter.allowAdminCommands] is
     * set, and an operation that returns or sets an authentication secret never unless
     * [ToolFilter.allowSecretTools] is. The secret gate is not a read-only question: two of those
     * operations are `GET`s, which `--read-only` would otherwise keep.
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
                    .filter { op -> !op.sensitive || filter.allowSecretTools }
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
            if (filter.allowSecretTools) add("SECRET TOOLS ENABLED")
        }
        return "registered ${selected.size}/$total API tools ($perFamily)" +
            if (flags.isEmpty()) "" else " [${flags.joinToString(", ")}]"
    }

    /** Every tag in [catalogs], once each (compared case-insensitively, as [select] does) and sorted. */
    fun tags(catalogs: Map<ApiFamily, Catalog>): List<String> =
        catalogs.values.flatMap { catalog -> catalog.ops.map { it.tag } }
            .distinctBy { it.lowercase() }
            .sortedBy { it.lowercase() }

    /** The entries of [values] that name no tag in [catalogs], so a tag filter on them matches nothing. */
    fun unknownTags(catalogs: Map<ApiFamily, Catalog>, values: Collection<String>): List<String> {
        val known = tags(catalogs).map { it.lowercase() }.toSet()
        return values.filter { it.lowercase() !in known }
    }

    /** The entries of [globs] that match no operation name in [catalogs]. */
    fun unmatchedGlobs(catalogs: Map<ApiFamily, Catalog>, globs: Collection<String>): List<String> {
        val names = catalogs.values.flatMap { catalog -> catalog.ops.map { it.name } }
        return globs.filter { glob -> globToRegex(glob).let { regex -> names.none { regex.matches(it) } } }
    }

    /**
     * The entries of [globs] that match at least one operation in [catalogs], and only operations
     * behind the secret gate. Such a glob is not a typo, so [unmatchedGlobs] stays quiet about it,
     * yet without `--allow-secret-tools` it registers nothing.
     */
    fun secretOnlyGlobs(catalogs: Map<ApiFamily, Catalog>, globs: Collection<String>): List<String> {
        val ops = catalogs.values.flatMap { it.ops }
        return globs.filter { glob ->
            val matched = globToRegex(glob).let { regex -> ops.filter { regex.matches(it.name) } }
            matched.isNotEmpty() && matched.all { it.sensitive }
        }
    }

    /**
     * Convert a shell-style glob (`*`, `?`) into an anchored regex; all other characters are literal.
     * Case-insensitive, like the tag filters: tool names are lowercase by catalog invariant, so a
     * case-sensitive `Get_Site*` could only ever match nothing.
     */
    internal fun globToRegex(glob: String): Regex {
        val sb = StringBuilder("^")
        for (ch in glob) {
            when (ch) {
                '*' -> sb.append(".*")
                '?' -> sb.append('.')
                else -> sb.append(Regex.escape(ch.toString()))
            }
        }
        return Regex(sb.append('$').toString(), RegexOption.IGNORE_CASE)
    }
}
