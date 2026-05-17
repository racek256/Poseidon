# Supply Chain Scanner — Issues Found During Real API Testing

Found while testing `POST /supplychain/quick-analyze`, `POST /supplychain/deep-analyze`, and `GET /supplychain/status` with 10+ real lockfiles across all supported ecosystems.

---

## Issue 1: OSV Severity → WarningLevel Mapping Broken (All Vulns Are "Medium")

**Severity: High**

**File:** `src/modules/supply_chain/mod.rs` — `WarningLevel::from_vulnerability_severity()`

**What happens:**
Every vulnerability returned by the OSV API is classified as `warning_level: "medium"`, regardless of whether the CVE is critical, high, or low.

**Root cause:**
```rust
fn from_vulnerability_severity(severity: &str) -> Self {
    if severity_lower.contains("critical") || severity_lower.contains("high") {
        WarningLevel::High
    } else if severity_lower.contains("medium") {
        WarningLevel::Medium
    } ...
}
```

The `severity` value passed in is the raw `score` string from the OSV API. Looking at the `OSVSeverity` struct:
```rust
pub struct OSVSeverity {
    pub r#type: Option<String>,  // e.g., "CVSS_V3"
    pub score: Option<String>,   // e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
```

The `score` field contains a **CVSS vector string** (like `CVSS:3.1/AV:N/AC:L/...`) or sometimes a numeric string. These DO NOT contain the words `"critical"`, `"high"`, `"medium"`, or `"low"` as substrings, so every call falls through to the `else` branch which returns `WarningLevel::Medium`.

**Evidence from testing:**
- `django 2.2.0` — **63 vulnerabilities**, all mapped to "medium" (includes known critical CVEs)
- `pillow 6.0.0` — **80 vulnerabilities**, all mapped to "medium"
- `k8s.io/kubernetes v1.21.0` — **19 vulnerabilities**, all mapped to "medium" (includes real criticals)
- `github.com/nats-io/nats-server v2.7.0` — **22 vulnerabilities**, all mapped to "medium"
- `github.com/hashicorp/vault v1.10.0` — **30 vulnerabilities**, all mapped to "medium"

**Fix:** Parse CVSS score/vector to extract severity, or use the OSV API's `database_specific.severity` field instead.

---

## Issue 2: pnpm-lock.yaml Parser Includes Leading `/` in Package Names

**Severity: Medium**

**File:** `src/modules/supply_chain/lockfile.rs` — `parse_pnpm_lock_yaml()`

**What happens:**
pnpm packages are parsed with a leading `/` in their name (e.g., `/lodash`, `/express`). This causes the typosquat checker to flag every package as a potential typosquat, because `/lodash` is Levenshtein distance 1 from `lodash`.

**Evidence from testing:**
```
pnpm-lock.yaml → overall_sentiment: "high"
  /lodash@4.17.21:  typosquat of 'lodash'  (Levenshtein 1)
  /express@4.16.0:  typosquat of 'express' (Levenshtein 1)
```

**Root cause:**
The parser starts collecting a package name when it sees a line like `/lodash@4.17.21:` and takes everything before the `@`, which includes the leading `/`. The existing unit test actually asserts this bug:
```rust
// lockfile.rs line 1206
assert_eq!(packages[0].name, "/lodash");  // bug: should be "lodash"
```

**Fix:** Strip leading `/` from the extracted name in `parse_pnpm_lock_yaml()`.

---

## Issue 3: OSV Vulnerability Summaries Show "No description"

**Severity: Medium**

**File:** `src/modules/supply_chain/osv.rs` — `OSVFullVulnerability` deserialization

**What happens:**
Every OSV vulnerability in the output shows as `"PYSEC-2023-74: No description"`. The `summary` field is never populated from the OSV API response.

**Evidence:**
```
"issues": [
    "PYSEC-2019-10: No description",
    "PYSEC-2019-11: No description",
    ...
    "PyPI package django/2.2.0 has 63 known vulnerabilities"
]
```

**Root cause:**
The `OSVFullVulnerability` struct expects a `summary` field from the OSV `/v1/vulns/{id}` endpoint. Either the field name in the OSV response has changed, or the API response structure differs from what's expected. The `fetch_vulnerability()` method populates `summary` from the `full.summary` field, but it comes back as `None` for every entry, causing the `"No description"` fallback in the output.

**Fix:** Inspect the actual OSV API response for `/v1/vulns/{id}` and update the deserialization to match. The field might be named differently or nested.

---

## Issue 4: Typosquat Detection False Positives on Legitimate Popular Packages

**Severity: Low**

**File:** `src/modules/supply_chain/typosquat.rs` — `TyposquatChecker::check_package()`

**What happens:**
When a package name happens to be within Levenshtein distance 2 of a less-popular package in the popular packages list, it gets flagged as a potential typosquat, even if the package is itself a legitimate and widely-used package.

**Evidence:**
- `next@14.0.0` (Next.js, a top npm package) flagged as:
  - Possible typosquat of `jest` (Levenshtein distance 2)
  - Possible typosquat of `nopt` (Levenshtein distance 2)

**Root cause:**
The fallback Levenshtein check runs against ALL packages in the popular list, but only skips exact name matches (not close matches for legitimate packages). The `@scoped/name` prefix handling also seems inconsistent — `next` has no `@` prefix but still gets compared against all non-scoped entries.

**Fix:** Add a second-level check: if the package being checked is itself a known popular package (in the top 1000 npm/PyPI downloads or similar), skip typosquat detection for it. Or add a whitelist of "known legitimate" packages.

---

## Issue 5: npm Ecosystem OSV Queries Return Empty for Known-Vulnerable Packages

**Severity: Medium**

**File:** `src/modules/supply_chain/osv.rs` — `OSVClient::query_batch_chunk()`

**What happens:**
Known-vulnerable npm packages like `lodash 4.17.20`, `express 4.16.0`, `axios 0.21.1` all return zero OSV results, even though these versions have known CVEs.

**Evidence:**
```
package-lock.json with 9 npm packages → 0 critical, 0 high, 0 medium, 0 low, 9 safe
  lodash@4.17.20:   safe (known CVE-2020-28500, CVE-2021-23337)
  express@4.16.0:   safe (known CVE-2019-17622)
  axios@0.21.1:     safe (known CVE-2021-3749)
```

The same scenario for PyPI packages with the same relative age works correctly:
```
requirements.txt with 8 PyPI packages → 0 critical, 0 high, 8 medium, 0 low, 0 safe
```

**Possible causes:**
1. OSV batch query format differs for npm ecosystem — the `version` field may need a prefix like `v` or the ecosystem name may need to match exactly (`npm` vs `npmjs`)
2. The OSV batch endpoint may have issues with certain `ecosystem` values
3. Rate-limiting or silent failure specific to npm queries

**Fix:** Add debug logging for empty OSV results, test the OSV batch API directly for npm packages, and verify the ecosystem string matches what OSV expects for npm (`"npm"` is correct per OSV docs, but worth verifying).

---

## Issue 6: OSV Vulnerability Fetching Redundant — N+1 HTTP Calls

**Severity: Low**

**File:** `src/modules/supply_chain/osv.rs` — `query_batch_chunk()`

**What happens:**
After the batch query returns vulnerability IDs, the client makes ONE HTTP request per vulnerability to fetch details:

```rust
for vuln_summary in &result.vulns {
    if let Ok(full) = self.fetch_vulnerability(&vuln_summary.id) {
        hydrated.push(full);
    }
}
```

For a lockfile with 100 packages where each has 5 vulns, that's 500 sequential GET requests to `https://api.osv.dev/v1/vulns/{id}`.

The OSV API supports batch vulnerability detail fetching (the response from `querybatch` already includes full vuln details if you set the right fields), but this implementation does batched IDs → individual fetches.

**Fix:** Check if the OSV batch response already contains full vulnerability details, or implement batched detail fetching if OSV supports it. Add parallelism (e.g., `thread::scope` or a small thread pool) for the individual fetches.

---

## Issue 7: Deep Analysis LLM Failure Not Clearly Reported

**Severity: Low**

**File:** `src/modules/supply_chain/deep_analysis.rs`

**What happens:**
When no LLM is configured, the commit analysis runs but returns `"verdict": "allow"` with `"confidence": 0.0` and 10 commit entries all showing `"reasons": ["LLM response could not be parsed"]`. The top-level `error` field is `null`.

This gives a false sense of security — the deep analysis "succeeds" but the AI part silently fails. Users might see `"verdict": "allow"` and think the commit analysis was clean, when in reality no analysis happened.

**Fix:** Surface a clear `"ai_status": "not_configured"` or similar field at the top level when the LLM is unavailable. Only populate `commit_analysis` data when analysis actually ran. Set `error` to a descriptive message.

---

## Issue 8: Registry Checker Only Supports 3 Ecosystems (PyPI, npm, crates.io)

**Severity: Low**

**File:** `src/modules/supply_chain/registry.rs` — `RegistryChecker::check_package()`

**What happens:**
The registry checker (yanked/deprecated/new-package warnings) only implements actual HTTP checks for PyPI, npm, and crates.io. All other ecosystems (Go, RubyGems, Packagist, Maven, NuGet, Pub, Hex) fall through to `check_generic_registry()` which returns an empty `Vec`. The OSV vulnerability check still works for these ecosystems, but registry-specific metadata is never checked.

```rust
pub fn check_package(&self, name: &str, version: &str, ecosystem: &str) -> Vec<String> {
    match ecosystem.to_lowercase().as_str() {
        "pypi" | "pip" | "pyproject" => { ... },
        "npm" | "nodejs" | "yarn" | "pnpm" => { ... },
        "crates.io" | "crates" | "cargo" | "rust" => { ... },
        _ => { Vec::new() },  // Go, RubyGems, Packagist, Maven, NuGet, Pub, Hex
    }
}
```

**Evidence:**
- Go packages like `k8s.io/kubernetes` — no registry check warnings (though OSV caught them)
- Ruby gems like `rack 2.2.3` — no registry check for yanked/deprecated status
- PHP packages like `laravel/framework 6.0.0` — no registry check

**Fix:** Implement registry checks for the most popular of the remaining ecosystems (RubyGems, Packagist, Go at minimum).

---

## Issue 9: `raw` Lockfile Content Fallback Skips OSV Checks

**Severity: Low**

**File:** `src/modules/supply_chain/mod.rs` — `handle_quick_analyze()`

**What happens:**
When the request body is not valid JSON, the handler falls back to treating the entire body as raw lockfile content:
```rust
} else {
    scanner.quick_analyze(body, None)  // filename = None
}
```

And `quick_analyze` passes `filename.unwrap_or("")` to `detect_lockfile_type("")`, which returns `None`, immediately returning an error:
```json
{ "overall_sentiment": "safe", "packages": [], "error": "Could not detect lockfile type from filename" }
```

This means any non-JSON request or raw-body approach silently fails with a "safe" sentiment, which could be misleading. An error should be surfaced differently from a "safe" scan result.

**Fix:** Return a 400 status code instead of a 200 with `"overall_sentiment": "safe"` when the lockfile type can't be detected, or add a separate `error` field that the client can distinguish from scan results.

---

## Summary

| # | Issue | Severity | Component |
|---|---|---|---|
| 1 | All OSV vulns map to "medium" regardless of severity | **High** | `mod.rs` — `from_vulnerability_severity` |
| 2 | pnpm-lock.yaml parser includes `/` in names → typosquat FPs | **Medium** | `lockfile.rs` — `parse_pnpm_lock_yaml` |
| 3 | OSV vulnerability summaries show "No description" | **Medium** | `osv.rs` — `fetch_vulnerability` |
| 4 | Typosquat false positives on legitimate packages | **Low** | `typosquat.rs` — `check_package` |
| 5 | npm ecosystem OSV queries return empty for vulnerable packages | **Medium** | `osv.rs` — `query_batch_chunk` |
| 6 | N+1 HTTP requests per vulnerability to OSV API | **Low** | `osv.rs` — `query_batch_chunk` |
| 7 | Deep analysis LLM failure silently reports "allow" | **Low** | `deep_analysis.rs` |
| 8 | Registry checker only supports 3/10 ecosystems | **Low** | `registry.rs` — `check_package` |
| 9 | Non-JSON request body silently returns "safe" with error | **Low** | `mod.rs` — `handle_quick_analyze` |
