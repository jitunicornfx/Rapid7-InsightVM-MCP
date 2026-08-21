# tools/

## `gen_catalog.py`

Generates the MCP tool catalog (`src/main/resources/catalog/v3.json`, `v4.json`) from the OpenAPI
documents in `specs/`. The server registers one tool per catalog entry at startup and never parses
the raw specifications.

```bash
python tools/gen_catalog.py          # regenerate after updating specs/
python tools/gen_catalog.py --check  # verify the committed catalog matches (run by ./gradlew check)
```

Python 3.10+, standard library only. Skip the Gradle check on machines without Python:
`./gradlew check -PskipCatalogCheck=true`.

### Rules encoded in the generator

| Concern | Rule |
|---|---|
| Tool name | `snake_case(operationId)`; cloud (v4) tools are prefixed `cloud_` to avoid the six name collisions with v3 (`getScans`, `getScan`, `startScan`, …). |
| `readOnlyHint` | `GET` operations. |
| `destructiveHint` | `DELETE`, or an `operationId` starting with `delete`, `remove` or `stop`. |
| `admin` | `POST /api/3/administration/commands` (arbitrary console command execution). Registered only with `--allow-admin-commands`, and then still requires `confirm="EXECUTE"`. |
| Parameters | Path and query only. The v4 `region` path parameter is dropped (it comes from `INSIGHTVM_REGION`). Array query parameters are sent `form`/`explode` style (`sort=a&sort=b`). |
| Request bodies | `$ref`s are inlined (cycle-guarded, depth ≤ 8). `readOnly: true` properties are removed — they are server-assigned and never valid in a request. `example`, `xml`, `title`, `discriminator` are stripped. |
| Descriptions | HTML stripped, entities decoded, whitespace collapsed, control characters removed, `<`/`>` neutralised, capped at 600 characters. |
| Responses | The first 2xx content type is recorded (`application/json`, `text/html`, `text/plain`, `application/zip`) so the runtime can choose the `Accept` header and the sanitiser. |

### Known quirks passed through from the specifications

* A handful of schemas declare `id` as `{type: object, format: int32}`; the catalog keeps the spec's shape.
* `UserEdit` references itself; the cycle is replaced with an opaque `object`.
* `/api/3/administration/commands` and the scan-engine shared secret endpoints use `text/plain`.
