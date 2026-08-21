# Security

This server sits between an LLM and two credentialed vulnerability-management APIs. Three things make that
sensitive: the model's tool calls are influenced by whatever the model has read (including attacker-authored text),
API responses contain attacker-influenced data (host names, banners, vulnerability proofs), and the HTTP transport
exposes a network surface that holds live credentials.

## Threat model

| Actor | Capability | What we protect |
|---|---|---|
| Attacker-controlled data in InsightVM (scanned hosts, banners, notes) | Gets rendered to the model and possibly to a client UI | Model instructions, client UI |
| A model that has been manipulated | Calls any registered tool with any arguments | API integrity, credential egress, console configuration |
| Local or network process that can reach `--http` | Sends arbitrary HTTP requests; a browser can be made to send them (DNS rebinding, CSRF) | Credential misuse |
| Network attacker between server and console | Intercepts or redirects traffic | Console credentials |

Out of scope: a compromised operator machine, a malicious bundled specification, or a compromised GitHub release
(see *Self-update*).

## Controls

### Prompt injection (data → model)

* Every API body is wrapped in a fence with an explicit preamble telling the model to treat it as data
  (`ToolSupport.wrapUntrusted`). Occurrences of the fence markers inside the data are rewritten so a payload cannot
  close the fence early. A regression test asserts the closing marker appears exactly once, at the very end.
* Tool names, descriptions and parameter descriptions come from the bundled OpenAPI documents. The generator strips
  HTML, decodes entities, removes control characters and caps length; the loader re-validates that no `<`/`>` survived
  (`CatalogLoader.validate`). Nothing the API returns at runtime ever becomes part of a tool definition.
* The two meta tools only emit server-authored JSON built from the catalog.

### XSS / markup (data → client UI)

* `text/html` responses (policy rationale, remediation, proof) are reduced to plain text: `<script>`/`<style>` blocks are
  removed with their content, comments and tags are stripped, entities are decoded, and the result is re-escaped so the
  output contains no `<`, `>` or bare `&` (`ResponseSanitizer.htmlToText`).
* JSON and plain-text responses have `<` and `>` replaced with `&lt;`/`&gt;` (`neutralizeMarkup`). Clients that render
  tool output as Markdown/HTML therefore cannot execute anything embedded in, say, a vulnerability proof. `&` is left
  alone so already-escaped data is not double-escaped; the transformation is reversible for the model.
* Control characters (except tab and newline) are scrubbed from all text, so terminal escape sequences in banners cannot
  reach a console client.
* Binary responses (`application/zip` log bundles) are never inlined: a JSON descriptor with size, SHA-256 and a capped
  base64 prefix is returned instead.

### Request integrity (model → API)

* URLs are built from the catalog's path template only. Path values go through `seg()`, which percent-encodes and
  refuses `.`/`..`; the model cannot redirect a call to a sibling endpoint.
* Unknown argument names are rejected, so nothing can be smuggled into the query string or body.
* Scalars are coerced against the declared schema (integer/boolean/number/enum); strings are capped at 4096 characters
  and may not contain CR, LF or NUL; arrays at 500 items; JSON bodies at 1 MiB and 32 levels (measured iteratively).
* Hypermedia links (`links[].href`, cursors) may only be followed when their parsed origin equals the configured base
  exactly — prefix tricks (`console.example.evil`) and userinfo tricks (`console.example@evil`) are rejected.

### Dangerous operations

* `POST /api/3/administration/commands` executes arbitrary console commands. It is **not registered** unless
  `--allow-admin-commands` / `INSIGHTVM_ALLOW_ADMIN_COMMANDS=1`, and even then the call must carry
  `confirm="EXECUTE"`. It is also excluded by `--read-only`.
* Every `DELETE`, and every operation whose id starts with `delete`, `remove` or `stop`, is annotated
  `destructiveHint=true`; all non-`GET` operations are `readOnlyHint=false`. Clients that honour annotations can prompt.
* `--read-only` registers only `GET` operations. Command-line flags can only tighten the environment's filters.

### Credential egress

* Redirects are never followed (`followRedirects = false`): a 3xx cannot bounce `Authorization`/`X-Api-Key` elsewhere.
* Console and cloud URLs must be `https` unless `INSIGHTVM_ALLOW_HTTP=1` is set deliberately.
* The console URL must be a bare origin (no path, query, fragment or embedded credentials).
* Secrets are redacted from every `toString()`; startup logs print hosts and regions only. stdout is reserved for the
  JSON-RPC stream and `System.out` is redirected to stderr in stdio mode.

### TLS to the Security Console

* Default: the JVM trust store with hostname verification.
* `INSIGHTVM_CONSOLE_CA_CERT`: trust exactly the certificates in the PEM file (private CA or the console's self-signed
  leaf); hostname verification stays on. The OkHttp client is built eagerly so a bad PEM fails at startup.
* `INSIGHTVM_CONSOLE_INSECURE_TLS=1`: disables verification, prints a warning banner. Lab use only.

### `--http` transport

| Control | Detail |
|---|---|
| Bearer token | `INSIGHTVM_MCP_AUTH_TOKEN`; compared with `MessageDigest.isEqual`. **Mandatory** when `--host` is not loopback — the server refuses to start otherwise. On loopback it is optional but a warning is logged. |
| Brute-force throttle | 20 failed attempts per client address per minute → `429` with `Retry-After`, checked before the token compare. Bounded memory (10 000 clients, oldest evicted). |
| DNS rebinding | On loopback binds the `Host` header must name the server (bind address, `localhost`, loopback literals, or an allow-listed origin's host) → else `421`. |
| Browser origins | Any request carrying `Origin` must match `INSIGHTVM_HTTP_ALLOWED_ORIGINS` exactly (scheme+host+port, default ports normalised) → else `403`. `*` is ignored. |
| CORS | Default-deny; only allow-listed origins receive CORS headers. Preflights skip the bearer check but not the origin check. |
| Request size | Declared `Content-Length` above 4 MiB → `413`. |
| SDK guard | The SDK's built-in DNS-rebinding plugin is disabled because it only understands localhost binds; the guard above runs before both the Streamable HTTP (`/mcp`) and legacy SSE (`/sse`) routes. |

### Resource limits

* Response bodies are streamed into a buffer capped at `INSIGHTVM_MAX_RESPONSE_BYTES` (5 MB default); the tool result
  states when truncation happened.
* Deeply nested hostile JSON cannot kill the session: `StackOverflowError` from the pretty-printer is caught and the raw
  body is used.
* All per-request work is bounded by `INSIGHTVM_TIMEOUT_MS`.

### Self-update

Ported from the InsightIDR server with its protections intact: exact-match GitHub host allow-list, a strict version-tag
regex as the only remote text that reaches the model, mandatory SHA-256 verified from disk, entry-point check on the
downloaded JAR, a cross-process lock, and staged swap-at-shutdown on Windows with rollback.

**Residual risk, stated plainly:** the digest comes from the same GitHub API response as the download URL, so a
compromise of the GitHub repository or release would not be detected. Set `INSIGHTVM_DISABLE_AUTO_UPDATE=1` (or
`--no-auto-update`) where that is unacceptable, or `INSIGHTVM_DISABLE_UPDATE_CHECK=1` to make no outbound call at all.

## Audit findings (v0.1.0)

The pre-release audit reviewed every file for the classic smells (`println` to stdout, secrets in strings, unbounded
`bodyAsText`, `anyHost()`, string-built URLs, subprocess execution) and walked the data flows above. Three findings
were fixed before release:

1. **Markup in JSON/plain output** — `<script>` inside a JSON string value would have reached a rendering client unescaped. Fixed by `neutralizeMarkup` on all textual output.
2. **Cleartext cloud override** — `INSIGHTVM_CLOUD_BASE_URL=http://…` was accepted silently, sending the API key in cleartext. Fixed: `https` required unless `INSIGHTVM_ALLOW_HTTP=1`.
3. **Bearer brute force** — failed authentications were unthrottled. Fixed with the per-client failure limiter.

Known, accepted:

* The request-size cap relies on `Content-Length`; a chunked upload is bounded by the SDK's own 4 MiB limit on the SSE
  message endpoint but not on the Streamable HTTP endpoint. Keep the server on loopback or behind a reverse proxy that
  enforces body limits if this matters.
* `INSIGHTVM_MAX_RESPONSE_BYTES` bounds memory, not model context: a 5 MB response is still a 5 MB tool result. Lower it
  for small-context clients.

## Reporting

Please report vulnerabilities privately via GitHub security advisories on the repository rather than public issues.
