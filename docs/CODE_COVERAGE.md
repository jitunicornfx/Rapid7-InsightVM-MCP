# Code coverage

Coverage is measured with JaCoCo and **enforced**: `./gradlew check` fails below 90 % line coverage
(`jacocoTestCoverageVerification` in `build.gradle.kts`).

```bash
./gradlew test jacocoTestReport            # HTML: build/reports/jacoco/test/html/index.html
./gradlew jacocoTestCoverageVerification   # the gate on its own
```

## Baseline at v0.2.1

| Counter | Coverage |
|---|---|
| Line | 93.3 % |
| Method | 92.1 % |
| Branch | 81.7 % |

| File | Line | Notes |
|---|---|---|
| `catalog/*` (loader, filter, schema builder, binder, tools) | 98–100 % | |
| `Rapid7Client.kt`, `ResponseSanitizer.kt`, `HttpTransportSecurity.kt` | 100 % | |
| `Config.kt`, `TlsSupport.kt` | 97–99 % | |
| `UpdateChecker.kt` / `UpdateInstaller.kt` | 98 % / 89 % | ported suites |
| `ResultBudget.kt` / `RecordLinks.kt` / `catalog/PagingDefaults.kt` | 96–100 % | the result-size machinery |
| `SpoolStore.kt` / `tools/ExportTools.kt` | 90–93 % | filesystem and paging-loop failure branches |
| `McpServerFactory.kt` | 86 % | notification delivery failure paths |
| `Main.kt` | 73 % | the update-install branches need a real GitHub release; both transports *are* exercised end-to-end |

## How the suite is built

* **`CatalogToolsTableDrivenTest`** — a JUnit `@TestFactory` produces one dynamic test per catalog operation (343).
  Each synthesises arguments from the tool's own input schema, calls the tool through a real in-process MCP
  client/server pair (`testutil/InMemoryTransport`, `McpTestHarness`) and asserts the HTTP request the tool produced:
  method, substituted path, every declared query parameter and nothing else, body shape and content type, auth header per
  API family, `Accept` header, plus annotations and the untrusted-data fence on the result. Adding an operation to the
  spec automatically adds a test.
* **`CatalogToolsBehaviourTest`** — sanitisation (HTML, binary, text), error hints per status, truncation, fence
  neutralisation, argument rejection, the admin-command and secret-tool gates, filters and the meta tools. It also
  checks that tool text and notices follow the configuration (page size, export tool, links), and pins the size of
  `tools/list`.
  `McpServerFactoryTest` checks that Servers built from one `CatalogTools.prepare` share every tool definition.
* **`HttpTransportSecurityTest`** — Ktor `testApplication` against the guard: bearer, throttle, Host/Origin, CORS
  preflight, size cap, helper functions.
* **`MainTest`** — Clikt option parsing through the `test()` helper, plus real transports: a stdio session over pipes
  and a Streamable HTTP session on an ephemeral port behind the guard.
* **`HttpRuntimeTest`** — the `--http` runtime on a real socket, driving the protocol by hand where the SDK client
  would hide the behaviour: the session cap (oldest closed and answered `404`, sessionless strays never evicting a
  live session, `DELETE` releasing at once, an evicted legacy stream ending), an update notice dropped when the client's stream opens late and delivered within the grace
  period, `insightvm_server_info` answering either way, a chunked body over 4 MiB refused on both transports (the
  guard sees no `Content-Length`, so this pins the SDK's own limit), and an allow-listed browser origin reaching a
  session on both transports through the real routes.
* **`UpdateStatusTest`** — every check and install state as `insightvm_server_info` reports it, including "could not
  tell" kept apart from "up to date", and no path in the payload.
* **`Rapid7ClientTest`, `TlsSupportTest`, `ConfigTest`, `ResponseSanitizerTest`, `ArgumentBinderTest`, `CatalogTest`,
  `McpServerFactoryTest`** — focused unit tests for each component; HTTP is stubbed with Ktor `MockEngine` through the
  `Rapid7Client(consoleEngine, cloudEngine)` seam.
* **`UpdateCheckerTest`, `UpdateInstallerTest`, `UpdateNotificationTest`** — the self-update refusal suite, ported.
* **`ResultBudgetTest`** — one test per rung of the degradation ladder, plus the error floor, the sample floor, the
  parse ceiling, the never-trim keys, surrogate safety and the "no notice on the happy path" invariant that the 343
  dynamic tests depend on.
* **`RecordLinksTest`** — v3/v4/bare-array shapes, depth limits, and that a 100,000-deep record cannot overflow the
  stack.
* **`PagingDefaultsTest`** — injection, clamping, and that a non-numeric size is left for the binder to reject.
* **`SpoolStoreTest`, `ExportToolsTest`** — label sanitisation and containment against hostile labels, the retention
  sweep, all three paging modes (v4 `metadata` included), every cap and a resume token that never repeats a written
  page, the retry at a smaller page size when a page exceeds the response cap, API error bodies kept inside the
  untrusted fence, a record too deep to encode, and refusal of unknown, filtered-out and state-changing tools. A
  suspending `Canned.delayMillis` drives the time budget (a slow page is abandoned, a page that cannot fit is not
  started); a `usableSpace()` override drives the disk reserve. Directory safety is OS-specific: the Windows tests
  check that a created directory carries only its owner's inheritable entry and that an existing one keeps its ACL;
  the POSIX tests (skipped on Windows) check the modes, that an existing directory is never chmodded, and that one
  others can write to is refused. The symlink test runs only where the account may create symbolic links.

`src/test/resources/tls/test-ca.pem` is a throw-away self-signed certificate generated for the TLS tests; it has no
private key in the repository and trusts nothing real. The two handshake tests in `TlsSupportTest` make their own
throw-away EC keys with the JDK's `keytool` at run time (a self-signed console, and a CA with a leaf it issued) and
serve them from a loopback `SSLServerSocket` through the real OkHttp client, so no private key is committed either;
they are skipped on a Java runtime without `keytool`.

## Gotchas

* JUnit silently skips test methods that return a value. `@Test fun x() = runBlocking { … }` is fine only because
  `runBlocking` returns `Unit` here; if a test's last expression is an assertion that returns a value, wrap it.
  Cross-check declared `@Test` counts against `build/test-results/test/TEST-*.xml` when in doubt.
* The catalog is loaded once per JVM in tests (`TEST_CATALOGS`); re-parsing 600 KB per test would dominate the run.
* `verifyCatalog` (part of `check`) re-runs `CatalogGenerator` and fails on drift; `CatalogGeneratorTest` asserts the same byte-for-byte.
