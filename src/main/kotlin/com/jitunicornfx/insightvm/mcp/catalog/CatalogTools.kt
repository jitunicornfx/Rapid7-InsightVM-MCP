package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.Config
import com.jitunicornfx.insightvm.mcp.Rapid7Client
import com.jitunicornfx.insightvm.mcp.ResponseSanitizer
import com.jitunicornfx.insightvm.mcp.SERVER_NAME
import com.jitunicornfx.insightvm.mcp.SERVER_VERSION
import com.jitunicornfx.insightvm.mcp.apiTool
import com.jitunicornfx.insightvm.mcp.stringOrNull
import com.jitunicornfx.insightvm.mcp.textResult
import io.ktor.http.ContentType
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import com.jitunicornfx.insightvm.mcp.JsonCodec

/**
 * Registers one MCP tool per selected catalog operation, plus two meta tools that help clients
 * navigate a large tool set.
 */
object CatalogTools {

    const val SERVER_INFO_TOOL = "insightvm_server_info"
    const val TOOL_GROUPS_TOOL = "insightvm_list_tool_groups"

    /** Register the selected operations on [server]; returns the number of API tools registered. */
    fun register(
        server: Server,
        client: Rapid7Client,
        config: Config,
        catalogs: Map<ApiFamily, Catalog>,
    ): List<CatalogFilter.Selection> {
        val filter = config.filter.copy(families = config.activeFamilies.intersect(config.filter.families))
        val selected = CatalogFilter.select(catalogs, filter)
        selected.forEach { (family, op) -> server.registerOperation(client, family, op) }
        server.registerMetaTools(config, catalogs, selected)
        return selected
    }

    internal fun Server.registerOperation(client: Rapid7Client, family: ApiFamily, op: CatalogOp) {
        apiTool(
            name = op.name,
            description = InputSchemaBuilder.describe(op, family),
            inputSchema = InputSchemaBuilder.build(op),
            readOnly = op.readOnly,
            destructive = op.destructive,
        ) { args ->
            if (op.admin) {
                require(args.stringOrNull(CatalogLoader.CONFIRM_PROPERTY) == InputSchemaBuilder.CONFIRM_VALUE) {
                    "This tool executes a command on the Security Console. Set confirm=\"${InputSchemaBuilder.CONFIRM_VALUE}\" to proceed."
                }
            }
            val bound = ArgumentBinder.bind(op, args)
            val response = client.request(
                family = family,
                method = bound.method,
                path = bound.path,
                query = bound.query,
                jsonBody = bound.jsonBody,
                rawBody = bound.rawBody,
                rawContentType = bound.rawContentType ?: ContentType.Text.Plain,
                accept = acceptFor(op),
            )
            ResponseSanitizer.toToolResult(response, op, family)
        }
    }

    /** `Accept` header matching the operation's documented success content type. */
    internal fun acceptFor(op: CatalogOp): ContentType = when (op.responses.success) {
        "text/html" -> ContentType.Text.Html
        "text/plain" -> ContentType.Text.Plain
        "application/json", "none" -> ContentType.Application.Json
        else -> ContentType.parse(op.responses.success)
    }

    private fun Server.registerMetaTools(config: Config, catalogs: Map<ApiFamily, Catalog>, selected: List<CatalogFilter.Selection>) {
        apiTool(
            name = SERVER_INFO_TOOL,
            description = "Describe this MCP server: version, which InsightVM APIs are configured, active tool filters and tool counts per API family.",
            inputSchema = ToolSchema(properties = buildJsonObject {}),
            readOnly = true,
        ) {
            textResult(pretty(serverInfo(config, catalogs, selected)))
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

    internal fun serverInfo(config: Config, catalogs: Map<ApiFamily, Catalog>, selected: List<CatalogFilter.Selection>): JsonElement = buildJsonObject {
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
        }
        put("totalTools", selected.size + 2)
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
