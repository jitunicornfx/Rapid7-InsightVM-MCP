package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.Config
import com.jitunicornfx.insightvm.mcp.Rapid7Client
import com.jitunicornfx.insightvm.mcp.ResponseSanitizer
import com.jitunicornfx.insightvm.mcp.ResultBudget
import com.jitunicornfx.insightvm.mcp.SERVER_NAME
import com.jitunicornfx.insightvm.mcp.SpoolStore
import com.jitunicornfx.insightvm.mcp.tools.ExportTools
import com.jitunicornfx.insightvm.mcp.SERVER_VERSION
import com.jitunicornfx.insightvm.mcp.apiTool
import com.jitunicornfx.insightvm.mcp.booleanOrNull
import com.jitunicornfx.insightvm.mcp.errorResult
import com.jitunicornfx.insightvm.mcp.stringOrNull
import com.jitunicornfx.insightvm.mcp.textResult
import io.ktor.http.ContentType
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import com.jitunicornfx.insightvm.mcp.JsonCodec

/**
 * Registers one MCP tool per selected catalog operation, plus meta tools that help clients navigate a
 * large tool set: two always, and the search-criteria reference whenever a console tool is selected.
 */
object CatalogTools {

    const val SERVER_INFO_TOOL = "insightvm_server_info"
    const val TOOL_GROUPS_TOOL = "insightvm_list_tool_groups"
    const val SEARCH_CRITERIA_TOOL = "insightvm_search_criteria"

    private val IDEMPOTENT_METHODS = setOf("PUT", "DELETE")

    /** Register the selected operations on [server]; returns the number of API tools registered. */
    fun register(
        server: Server,
        client: Rapid7Client,
        config: Config,
        catalogs: Map<ApiFamily, Catalog>,
        spool: SpoolStore = SpoolStore.active,
    ): List<CatalogFilter.Selection> {
        val filter = config.filter.copy(families = config.activeFamilies.intersect(config.filter.families))
        val selected = CatalogFilter.select(catalogs, filter)
        // Settled before any tool is registered: the paged tools' text and the truncation notices
        // recommend the export tool, and may do so only when it will be registered below.
        val exportEnabled = config.exportEnabled
        val budget = ResultBudget(maxChars = config.maxResultChars, exportAvailable = exportEnabled)
        // A binary payload spills to the same directory the export tool writes to, so an operator who
        // disabled filesystem writes gets none from this path either.
        val binarySpool = spool.takeUnless { config.exportDisabled }
        selected.forEach { (family, op) -> server.registerOperation(client, family, op, config, budget, binarySpool) }
        // The reference serves console tools only: v4 filters are expressions, not field/operator pairs.
        val criteriaEnabled = selected.any { it.family == ApiFamily.CONSOLE }
        server.registerMetaTools(config, catalogs, selected, 2 + listOf(exportEnabled, criteriaEnabled).count { it })
        if (criteriaEnabled) server.registerSearchCriteriaTool(SearchCriteria.bundled)
        if (exportEnabled) {
            with(ExportTools) { server.registerExportTool(client, config, selected, spool) }
        }
        return selected
    }

    internal fun Server.registerOperation(
        client: Rapid7Client,
        family: ApiFamily,
        op: CatalogOp,
        config: Config,
        budget: ResultBudget = ResultBudget.active,
        spool: SpoolStore? = null,
    ) {
        val text = ToolTextContext.of(config)
        // Like the description, a notice recommends the export tool only for an operation it would
        // accept; for a write or a secret it would answer with a refusal.
        val opBudget = if (ExportTools.exportable(op)) budget else budget.copy(exportAvailable = false)
        apiTool(
            name = op.name,
            description = InputSchemaBuilder.describe(op, family, text),
            inputSchema = InputSchemaBuilder.build(op, text),
            readOnly = op.readOnly,
            destructive = op.destructive,
            // By HTTP semantics a repeated PUT or DELETE leaves the state the first one did; a
            // repeated POST may create a second record or start a second scan.
            idempotent = op.method in IDEMPOTENT_METHODS,
        ) { args ->
            if (op.admin) {
                require(args.stringOrNull(CatalogLoader.CONFIRM_PROPERTY) == InputSchemaBuilder.CONFIRM_VALUE) {
                    "This tool executes a command on the Security Console. Set confirm=\"${InputSchemaBuilder.CONFIRM_VALUE}\" to proceed."
                }
            }
            // include_links is this server's own knob, not an API parameter: read it, then remove it
            // before binding or the binder's unknown-parameter guard would reject every paged call.
            val keepLinks = args.booleanOrNull(CatalogLoader.INCLUDE_LINKS_PROPERTY) ?: config.keepRecordLinks
            val apiArgs = JsonObject(args - CatalogLoader.INCLUDE_LINKS_PROPERTY)
            val bound = ArgumentBinder.bind(op, PagingDefaults.apply(op, apiArgs, config.defaultPageSize))
            val response = client.request(
                family = family,
                method = bound.method,
                path = bound.path,
                query = bound.query,
                jsonBody = bound.jsonBody,
                rawBody = bound.rawBody,
                rawContentType = bound.rawContentType ?: ContentType.Text.Plain,
                accept = acceptFor(op),
                expectBinary = op.responses.binary,
            )
            ResponseSanitizer.toToolResult(response, op, family, opBudget, keepLinks, spool)
        }
    }

    /**
     * `Accept` header matching the operation's documented success content type.
     *
     * A binary operation accepts any type ([ContentType.Any]). Its declared label is a poor guide to
     * what the console serves (download_report declares JSON for a report that is usually GZip), and
     * a controller that produces one type answers 406 to an `Accept` naming another.
     */
    internal fun acceptFor(op: CatalogOp): ContentType = when {
        op.responses.binary -> ContentType.Any
        else -> when (op.responses.success) {
            "text/html" -> ContentType.Text.Html
            "text/plain" -> ContentType.Text.Plain
            "application/json", "none" -> ContentType.Application.Json
            else -> ContentType.parse(op.responses.success)
        }
    }

    private fun Server.registerMetaTools(
        config: Config,
        catalogs: Map<ApiFamily, Catalog>,
        selected: List<CatalogFilter.Selection>,
        metaToolCount: Int,
    ) {
        apiTool(
            name = SERVER_INFO_TOOL,
            description = "Describe this MCP server: version, which InsightVM APIs are configured, active tool filters and tool counts per API family.",
            inputSchema = ToolSchema(properties = buildJsonObject {}),
            readOnly = true,
        ) {
            textResult(pretty(serverInfo(config, catalogs, selected, metaToolCount)))
        }
        apiTool(
            name = TOOL_GROUPS_TOOL,
            description = "List the available tools grouped by API tag (e.g. Site, Asset, Vulnerability). Optionally restrict to one tag. Use this to discover the right tool when the list is long.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("tag") {
                        put("type", "string")
                        put("description", "Only list tools for this tag (case-insensitive).")
                    }
                },
            ),
            readOnly = true,
        ) { args ->
            val tag = args.stringOrNull("tag")?.trim()?.lowercase()
            textResult(pretty(toolGroups(selected, tag)))
        }
    }

    /**
     * The console's search-criteria reference, which the filter schemas of find_assets, asset groups,
     * tags and dynamic sites point at. Its text comes from the bundled reference, never from the API.
     */
    internal fun Server.registerSearchCriteriaTool(reference: SearchCriteriaReference) {
        apiTool(
            name = SEARCH_CRITERIA_TOOL,
            description = "The Security Console's search-criteria reference: the fields a filter can name, the operators each " +
                "field accepts, the values of enumerated fields, and the value, lower or upper property each operator reads. " +
                "Use it to build the filters of find_assets and of asset group and tag search criteria (kind \"asset\", the " +
                "default), or of a dynamic site's discovery search criteria (kind \"discovery\"). Pass field to look up one field.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("kind") {
                        put("type", "string")
                        putJsonArray("enum") { SearchCriteria.Kind.entries.forEach { add(it.id) } }
                        put("description", "Which criteria: \"asset\" (default) or \"discovery\".")
                    }
                    putJsonObject("field") {
                        put("type", "string")
                        put("description", "Only this field (case-insensitive), with the properties each of its operators reads.")
                    }
                },
            ),
            readOnly = true,
        ) { args ->
            val kind = args.stringOrNull("kind")?.let { SearchCriteria.Kind.fromId(it) } ?: SearchCriteria.Kind.ASSET
            SearchCriteria.render(reference, kind, args.stringOrNull("field"))?.let { textResult(it) }
                ?: errorResult(
                    "No ${kind.id} search-criteria field has that name. Call $SEARCH_CRITERIA_TOOL without 'field' to list them" +
                        if (kind == SearchCriteria.Kind.ASSET) ", or with kind \"discovery\" for a dynamic site's discovery fields." else ".",
                )
        }
    }

    internal fun serverInfo(
        config: Config,
        catalogs: Map<ApiFamily, Catalog>,
        selected: List<CatalogFilter.Selection>,
        metaToolCount: Int = 2,
    ): JsonElement = buildJsonObject {
        put("server", SERVER_NAME)
        put("version", SERVER_VERSION)
        putJsonObject("apis") {
            for (family in ApiFamily.entries) {
                putJsonObject(family.id) {
                    put("name", family.displayName)
                    put("configured", family in config.activeFamilies)
                    catalogs[family]?.let { put("catalogOperations", it.ops.size); put("specVersion", it.meta.specVersion) }
                    put("registeredTools", selected.count { it.family == family })
                    when (family) {
                        ApiFamily.CONSOLE -> config.console?.let { put("baseUrl", it.baseUrl); put("insecureTls", it.insecureTls) }
                        ApiFamily.CLOUD -> config.cloud?.let { put("region", it.region.code); put("baseUrl", it.baseUrl) }
                    }
                }
            }
        }
        putJsonObject("filters") {
            put("readOnly", config.filter.readOnly)
            putJsonArray("tags") { config.filter.tags.sorted().forEach { add(it) } }
            putJsonArray("excludeTags") { config.filter.excludeTags.sorted().forEach { add(it) } }
            putJsonArray("tools") { config.filter.nameGlobs.forEach { add(it) } }
            put("adminCommandsEnabled", config.filter.allowAdminCommands)
            put("secretToolsEnabled", config.filter.allowSecretTools)
        }
        put("totalTools", selected.size + metaToolCount)
    }

    internal fun toolGroups(selected: List<CatalogFilter.Selection>, tag: String?): JsonElement {
        val groups = selected.groupBy { it.family to it.op.tag }
            .filterKeys { (_, t) -> tag == null || t.lowercase() == tag }
            .toSortedMap(compareBy<Pair<ApiFamily, String>> { it.first.ordinal }.thenBy { it.second })
        return buildJsonArray {
            groups.forEach { (key, ops) ->
                add(
                    buildJsonObject {
                        put("api", key.first.id)
                        put("tag", key.second)
                        put("count", ops.size)
                        putJsonArray("tools") {
                            ops.sortedBy { it.op.name }.forEach { sel ->
                                add(
                                    buildJsonObject {
                                        put("name", sel.op.name)
                                        put("method", sel.op.method)
                                        put("path", sel.op.path)
                                        if (sel.op.summary.isNotBlank()) put("summary", sel.op.summary)
                                        if (sel.op.destructive) put("destructive", true)
                                    },
                                )
                            }
                        }
                    },
                )
            }
        }
    }

    private fun pretty(element: JsonElement): String = JsonCodec.pretty.encodeToString(JsonElement.serializer(), element)
}
