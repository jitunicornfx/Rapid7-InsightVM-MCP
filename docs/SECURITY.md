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
  the layout HTML they use, decodes entities, removes control characters and caps length. It then neutralises anything
  that could still open markup: a `<` before a letter, `/`, `!` or `?` becomes `‹`, so an encoded `&lt;script&gt;`
  ends up as `‹script›`. A bare `<` or `>` cannot start a tag and is left alone, because the v4 query language is
  written with it (`cvss_score >= 9`). The loader re-validates that no markup opener survived in a tool's summary or
  description (`CatalogLoader.validate`). Nothing the API returns at runtime ever becomes part of a tool definition.
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

* URLs are built from the catalog's path template only. Path values go through `seg()`, which percent-encodes them,
  including the path-parameter delimiter `;` (sent as `%3B`), and refuses `.`/`..` whether alone or ahead of a `;`
  (`..;` is `..` to a Tomcat-style container, which strips `;...` before it normalises the path); the model cannot
  redirect a call to a sibling or parent endpoint.
* Unknown argument names are rejected, so nothing can be smuggled into the query string or body.
* Scalars are coerced against the declared schema (integer/boolean/number/enum); strings are capped at 4096 characters
  and may not contain CR, LF or NUL; arrays at 500 items; JSON bodies at 1 MiB and 32 levels (measured iteratively).
* The server never requests a URL taken from an API response. Hypermedia links (`links[].href`) are data it passes
  on, never follows; paging uses a page index or the API's opaque cursor token, which goes back through the argument
  binder like any other value. Every request targets the configured base URL plus a catalog path.

### Dangerous operations

* `POST /api/3/administration/commands` executes arbitrary console commands. It is **not registered** unless
  `--allow-admin-commands` / `INSIGHTVM_ALLOW_ADMIN_COMMANDS=1`, and even then the call must carry
  `confirm="EXECUTE"`. It is also excluded by `--read-only`.
* Every write is annotated `destructiveHint=true` unless it only adds (its id starts with `create`, `add`, `start`,
  `generate`, `tag` or `reconnect`): 114 of the 152 writes, including every `DELETE`, every `PUT` that replaces or
  updates state, scan and status changes, password and 2FA resets, and `execute_command`. The default is destructive,
  so a verb a future spec adds is flagged until someone looks at it. `PUT` and `DELETE` tools also carry
  `idempotentHint=true`. Every write is `readOnlyHint=false`. Clients that honour annotations can prompt.
* `readOnlyHint=true` goes on every `GET` and on five POST searches that only query (`find_assets`,
  `sonar_query_search`, `cloud_get_sites`, `cloud_search_integration_assets`,
  `cloud_search_integration_vulnerabilities`). They are pinned by method and path, and the catalog loader refuses any
  other non-`GET` marked read-only.
* `--read-only` registers only those reads (191 tools). Command-line flags can only tighten the environment's filters.
* On/off variables accept only `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`. Any other value stops the server,
  so a typo such as `INSIGHTVM_READ_ONLY=y` cannot leave a safety flag off while every mutating tool is registered.

### Credential egress

* Redirects are never followed (`followRedirects = false`): a 3xx cannot bounce `Authorization`/`X-Api-Key` elsewhere.
  The tool result says why the call stopped and which setting to check, and never quotes the `Location` it was sent.
* Console and cloud URLs must be `https` unless `INSIGHTVM_ALLOW_HTTP=1` is set deliberately.
* The console URL must be a bare origin (no path, query, fragment or embedded credentials).
* Secrets are redacted from every `toString()`; startup logs print hosts and regions only. stdout is reserved for the
  JSON-RPC stream and `System.out` is redirected to stderr in stdio mode.
* `INSIGHTVM_API_KEY`, `INSIGHTVM_CONSOLE_2FA_TOKEN` and `INSIGHTVM_MCP_AUTH_TOKEN` are trimmed and must then be
  visible ASCII, or startup fails naming the variable and a position, never the value. Ktor and OkHttp reject a bad
  header value at request time with an exception that quotes it, so these values are checked before they can become
  headers. As a second line, a tool error never repeats the text of such an exception, or of one that quotes a
  response's malformed `Content-Type`; it says what failed in fixed words.

### TLS to the Security Console

* Default: the JVM trust store with hostname verification.
* `INSIGHTVM_CONSOLE_CA_CERT`: trust exactly the certificates in the PEM file (private CA or the console's self-signed
  leaf); hostname verification stays on. The OkHttp client is built eagerly so a bad PEM fails at startup.
* `INSIGHTVM_CONSOLE_INSECURE_TLS=1`: disables verification, prints a warning banner. Lab use only.

### `--http` transport

| Control | Detail |
|---|---|
| Bearer token | `INSIGHTVM_MCP_AUTH_TOKEN`; compared with `MessageDigest.isEqual`. **Mandatory, and at least 32 characters,** when `--host` is not loopback — the server refuses to start otherwise, because the throttle below is per address and does not stop guesses spread across addresses. On loopback it is optional, but a missing or shorter token is warned about. |
| Brute-force throttle | 20 failed attempts per client address per minute → `429` with `Retry-After`, checked before the token compare. Bounded memory (10 000 clients, oldest evicted). |
| DNS rebinding | On loopback binds the `Host` header must name the server (bind address, `localhost`, loopback literals, or an allow-listed origin's host) → else `421`. |
| Browser origins | Any request carrying `Origin` must match `INSIGHTVM_HTTP_ALLOWED_ORIGINS` exactly (scheme+host+port, default ports normalised) → else `403`. `*` is ignored. |
| CORS | Default-deny; only allow-listed origins receive CORS headers. Preflights skip the bearer check but not the origin check. |
| Request size | Declared `Content-Length` above 4 MiB → `413`. |
| SDK guard | The SDK's built-in DNS-rebinding plugin is disabled because it only understands localhost binds; the guard above runs before both the Streamable HTTP (`/mcp`) and legacy SSE (`/sse`) routes. |

### Resource limits

Two tiers, because they defend different things:

* **Wire bytes** — response bodies are streamed into a buffer capped at `INSIGHTVM_MAX_RESPONSE_BYTES` (16 MiB
  default, hard ceiling 256 MiB so an environment typo cannot exhaust the heap). This bounds memory only. The cap is
  applied in `Long` arithmetic, and a body cut mid-character has its incomplete trailing UTF-8 sequence removed so
  decoding cannot yield U+FFFD.
* **Rendered characters** — `INSIGHTVM_MAX_RESULT_CHARS` (200,000, ~50k tokens) bounds what reaches the model, and is
  measured *after* markup neutralisation so escaping cannot inflate a result past the ceiling. There is deliberately
  no unlimited value; the floor is 2,000 so a misconfiguration cannot erase a diagnostic. An error body is never
  trimmed below 4,000 characters, because a non-2xx body is what the model needs to correct itself.
* The budget degrades through four rungs — pretty, compact, structural array trim, line-aware cut — and never throws:
  `StackOverflowError` from deeply nested hostile JSON is caught at every rung, and a body above 12M characters is
  never parsed into a tree at all. A structural trim keeps the document valid, parseable JSON and never touches
  `links`, `page` or `metadata`.
* Every truncation notice is server-authored — only integers are interpolated — and is emitted **outside** the
  untrusted-data fence, so API content can never forge one. A cut never splits a surrogate pair.
* Binary payloads are inlined only up to 4 KiB of base64; anything larger goes to a file (below).
* All per-request work is bounded by `INSIGHTVM_TIMEOUT_MS`.

### Spooled results

`insightvm_export_to_file` is the only tool that writes to the local filesystem, and binary payloads spill through
the same store. Both are removed by `INSIGHTVM_DISABLE_EXPORT=1`, and the export tool is also removed by
`--read-only` (whose contract is that nothing changes, and a file on disk is a change). It is registered with
`readOnlyHint=false`, so a client still prompts for it.

*No caller-controlled path.* Four independent controls:

1. The input schema has no `path`, `file`, `filename`, `directory` or `output` property, and the handler reads only
   its own declared keys. There is no code path from a tool argument to a filesystem location.
2. The file name's label is server-derived (the catalog tool's own name, already validated against
   `^[a-z0-9_]{1,64}$`) and is *still* sanitised: lower-cased, everything outside `[a-z0-9]` collapsed to `-`,
   capped at 40 characters. `..` and `../../etc/passwd` cannot survive.
3. `Files.createTempFile` creates the file with `O_CREAT|O_EXCL`, so it cannot follow a pre-planted symlink or
   collide with a concurrent export under `--http`, and it rejects a prefix containing a path separator. The fixed
   `insightvm-export-` prefix also means the name can never be a Windows reserved device name.
4. A `normalize().startsWith(directory)` post-condition proves containment anyway.

The directory is created lazily and carries a `README.txt` warning — the only artefact that reaches someone who finds it
later without having seen the tool's summary. Files are swept after `INSIGHTVM_SPOOL_RETENTION_HOURS`, and only files
carrying this server's own prefix and suffixes are ever swept.

**Permissions are POSIX-only.** On POSIX filesystems the directory is hardened to `rwx------` (files `rw-------`)
*before* the first file is written. On Windows — a primary target for this server — `PosixFileAttributeView` is
unsupported, so the hardening step is deliberately a no-op and the spool inherits the ACL of its parent. Under the
default location (`%USERPROFILE%\.rapid7-insightvm-mcp\spool`) that is normally the running account alone, but it is
inherited rather than enforced: an operator who relocates the spool with `INSIGHTVM_SPOOL_DIR` owns that ACL. Treat the
spool as sensitive storage on Windows and place it accordingly.

An export cannot be used to reach a tool the operator hid: the target is resolved against the **registered
selection**, not the raw catalog, so `--tags`, `--tools`, `--api` and `--read-only` all still apply. Only operations
the catalog marks read-only can be exported, the same set `--read-only` keeps: every `GET` and the five POST
searches, which the loader pins by method and path. `admin`/`destructive` operations are refused unconditionally
regardless. Every page goes through the normal
`ArgumentBinder`, so unknown-parameter rejection, type coercion, string bounds and path-segment encoding apply
unchanged. Paging uses a page index or the API's own opaque cursor token — never a URL taken from a response body,
so no request target is ever attacker-controlled. Runs are bounded by pages, records, bytes and wall-clock, and the
volume must have 256 MiB free before the first API call is spent.

### Self-update

Ported from the InsightIDR server with its protections intact: exact-match GitHub host allow-list, a strict version-tag
regex as the only remote text that reaches the model, mandatory SHA-256 verified from disk, entry-point check on the
downloaded JAR, a cross-process lock, and staged swap-at-shutdown on Windows with rollback.

Windows refuses to move anything over a JAR a JVM is running from, so there the update is written into the JAR in place
as the server exits. That rewrite is guarded:

* **Other servers.** Stdio deployment runs one server per client from the same JAR, each loading classes from it
  lazily. Every server holds a shared lock on `<jar>.running` for as long as it runs, and the exiting server rewrites
  the JAR only if it can take that lock exclusively. While any other server is running from the JAR, the staged
  update is discarded and fetched again on a later start.
* **Downgrades.** The installed JAR's SHA-256 is recorded when the update is staged. If the JAR has changed by the time
  the server exits (another server installed a newer release meanwhile), the stale stage is discarded, not written.
* **Durability.** The backup and the new bytes are each forced to disk before the backup is deleted, so a power cut
  cannot leave neither a working JAR nor a backup.
* **Permissions.** On POSIX, where the new JAR is moved into place, it first gets the old JAR's permissions; a warning
  is printed when the move also changes the file's owner.

Housekeeping: the `<jar>.update.lock` and `<jar>.running` sidecars are 0-byte lock carriers and are never deleted.
Abandoned `<jar>.*.new` / `<jar>.bak` files older than 24 hours are swept at startup and before each install (only
files carrying this JAR's own name prefix). A server with an update pending re-stamps its staged file every four hours
and holds it open (which on Windows refuses another process's delete), so a sibling's sweep does not remove it.

**Residual risk, stated plainly:** the digest comes from the same GitHub API response as the download URL, so a
compromise of the GitHub repository or release would not be detected. Set `INSIGHTVM_DISABLE_AUTO_UPDATE=1` (or
`--no-auto-update`) where that is unacceptable, or `INSIGHTVM_DISABLE_UPDATE_CHECK=1` to make no outbound call at all.

Also residual: a server that starts during the brief in-place rewrite at another server's exit can read a half-written
JAR and fail to start, or fail on a later class load. Only versioned install paths would close that window.

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
* A structural trim leaves the `page`/`metadata` object describing the full page the API returned, so its counts will
  not match the number of records left in the document. Both the in-band `_mcp_truncated` marker and the
  authoritative out-of-band notice say so explicitly.
* Raising `INSIGHTVM_MAX_RESPONSE_BYTES` raises worst-case heap (roughly three times the cap while a body is decoded).
  The 12M-character parse ceiling is the real guard; do not raise the wire cap without lowering it. Run with at least
  `-Xmx512m`.
* Spooled files hold tenant vulnerability data in cleartext on the server's disk. They are user-only and swept, but
  anyone with that account can read them. Set `INSIGHTVM_DISABLE_EXPORT=1` where that is unacceptable.

## Reporting

Please report vulnerabilities privately via GitHub security advisories on the repository rather than public issues.
