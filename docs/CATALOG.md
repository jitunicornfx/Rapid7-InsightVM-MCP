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
| `readOnlyHint` | `GET` operations, plus five POST searches that only query: `POST /api/3/assets/search`, `/api/3/sonar_queries/search`, `/v4/integration/assets`, `/v4/integration/sites` and `/v4/integration/vulnerabilities` (`CatalogLoader.QUERY_ONLY_OPS`). The loader refuses a catalog that marks any other non-`GET` read-only, or one of these five a write. `--read-only` and the export tool both go by this flag. |
| `destructiveHint` | Every operation that is not read-only, unless its `operationId` starts with `create`, `add`, `start`, `generate`, `tag` or `reconnect` followed by a capital letter. MCP defines `false` as "only additive updates", so the default is destructive: a `PUT` that replaces a list (`set_site_scan_schedules` with `[]` removes every schedule), a status change, a password or 2FA reset, and `execute_command` are all destructive. A `DELETE` and the `admin` operation are destructive whatever their id. |
| `idempotentHint` | Not stored in the catalog: set at registration on every `PUT` and `DELETE`, `false` on other writes, and absent on reads, where MCP gives it no meaning. |
| `admin` | `POST /api/3/administration/commands` (arbitrary console command execution). Registered only with `--allow-admin-commands`, and then still requires `confirm="EXECUTE"`. |
| Parameters | Path and query only. The v4 `region` path parameter is dropped (it comes from `INSIGHTVM_REGION`). Array query parameters are sent `form`/`explode` style (`sort=a&sort=b`); `sort` is an array in both families, although v4 declares it a string, because its own description says it repeats. A parameter with a scalar type keeps no `properties` or `required`: v4 wraps several path ids in an object component (`ScanId`, `AssetKey`), but the value is one string. |
| Request bodies | `$ref`s are inlined, cycle-guarded and at most 8 nested `$ref`s deep; plain JSON nesting is not limited. `readOnly: true` properties are removed — they are server-assigned and never valid in a request. `example`, `xml`, `title` are stripped. A `discriminator` beside `oneOf`/`anyOf` is stripped; one whose subtypes are named only in its `mapping` (`SharedCredentialAccount`) is flattened: the subtypes' properties are merged into the base (the base's own win, then the first definition), each merged field names the values it applies to, and the base description lists the fields for each value. Any other discriminator fails the build. A JSON body that declares a `format: binary` property fails the build; `activateLicense`'s, which its spec says must be sent as `multipart/form-data`, is dropped, leaving the `key` parameter. |
| Schema types | Below the root of a parameter or body, a node with no `type` gets one when it plainly has one: `items` → array, `properties`/`additionalProperties` → object, a string `enum` → string, `int32`/`int64` → integer, `float`/`double` → number, other known formats → string. A `format` outside the OpenAPI/JSON Schema set is dropped (v4 `sort` declared `<property>[,ASC\|DESC]`). |
| Descriptions | Only the layout tags the specifications use (`a b br code div em i li ol p pre span strong table tbody td th thead tr ul`) are stripped; entities decoded (unknown named entities fail the build); control characters removed; whitespace collapsed. Anything else that could open markup — a `<` before a letter, `/`, `!` or `?` — is neutralised to `‹…›`, so `<property>` survives as `‹property›`, while comparison operators such as `>=` stay as written. Text that is only unrendered `${…}` template keys is dropped, and so is an array item description that repeats the array's own. Capped at 600 characters (400 for parameters and properties, 200 for a field merged from a discriminator subtype). |
| Responses | The first 2xx content type is recorded (`application/json`, `text/html`, `text/plain`, `application/zip`) so the runtime can choose the `Accept` header and the sanitiser. |

### Known quirks passed through from the specifications

* A handful of schemas declare `id` as `{type: object, format: int32}`; the catalog keeps the spec's shape.
* `UserEdit` and v4's `ScanForm` reference themselves; each cycle is replaced with an opaque `object`.
* `/api/3/administration/commands` and the scan-engine shared secret endpoints use `text/plain`.

### Spec defects corrected by the generator

* `RangeResource.from` and `RiskTrendResource.from` (report trends) are declared an object whose enum ends in the
  literal `<date>`, which no value satisfies. They are overridden to a string: a duration (`P1Y`, `P6M`, `P3M`, `P1M`)
  or an ISO-8601 date.
* v4 descriptions that are only unrendered template keys (`${scanid.id.description}, …`) are dropped.
