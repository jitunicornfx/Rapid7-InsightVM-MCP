# Catalog generation

`CatalogGenerator` (`src/main/kotlin/com/jitunicornfx/insightvm/mcp/catalog/CatalogGenerator.kt`) generates the MCP tool catalog (`src/main/resources/catalog/v3.json`, `v4.json`) from the OpenAPI
documents in `specs/`. The server registers one tool per catalog entry at startup and never parses
the raw specifications.

The OpenAPI documents are **not committed**. To regenerate, download them from Rapid7 and place them at
`specs/insightvm-console-v3.json` (Security Console API v3) and `specs/insightvm-cloud-v4.json` (Cloud Integrations
API v4); the folder is git-ignored. `verifyCatalog` and the spec-backed tests skip automatically when it is absent.
Each catalog records the SHA-256 of the document it was generated from (`meta.specSha256`).

```bash
./gradlew generateCatalog   # regenerate after updating specs/
./gradlew verifyCatalog     # verify the committed catalog matches (part of ./gradlew check)
```

The generator serialises through the runtime's own `CatalogModel` data classes and validates with
`CatalogLoader.validate`, so the catalog can never drift from what the server expects. Output is deterministic
(one-space indent, LF); `CatalogGeneratorTest` asserts the committed files are byte-identical to a fresh run.

### Rules encoded in the generator

| Concern | Rule |
|---|---|
| Tool name | `snake_case(operationId)`; cloud (v4) tools are prefixed `cloud_` to avoid the six name collisions with v3 (`getScans`, `getScan`, `startScan`, …). |
| `readOnlyHint` | `GET` operations. |
| `destructiveHint` | `DELETE`, or an `operationId` starting with `delete`, `remove` or `stop`. |
| `admin` | `POST /api/3/administration/commands` (arbitrary console command execution). Registered only with `--allow-admin-commands`, and then still requires `confirm="EXECUTE"`. |
| Parameters | Path and query only. The v4 `region` path parameter is dropped (it comes from `INSIGHTVM_REGION`). Array query parameters are sent `form`/`explode` style (`sort=a&sort=b`). |
| Request bodies | `$ref`s are inlined (cycle-guarded, depth ≤ 8). `readOnly: true` properties are removed — they are server-assigned and never valid in a request. `example`, `xml`, `title`, `discriminator` are stripped. |
| Descriptions | HTML stripped, entities decoded (unknown named entities fail the build), whitespace collapsed, control characters removed, `<`/`>` neutralised, capped at 600 characters. |
| Responses | The first 2xx content type is recorded (`application/json`, `text/html`, `text/plain`, `application/zip`) so the runtime can choose the `Accept` header and the sanitiser. |

### Known quirks passed through from the specifications

* A handful of schemas declare `id` as `{type: object, format: int32}`; the catalog keeps the spec's shape.
* `UserEdit` references itself; the cycle is replaced with an opaque `object`.
* `/api/3/administration/commands` and the scan-engine shared secret endpoints use `text/plain`.
