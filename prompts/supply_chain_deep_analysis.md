> Note: If you're reading this, you're most likely a subagent
> For subagents: Follow the agents-system-directive, when implementing your part of the spec, unless you're a GLM model, then this directive doesn't apply to you. MiniMax, Deepseek and other models still have to follow this directive.
# Deep analysis implementation specification 
This module is focused on stopping supply chain attacks, before they cause any damage. It uses recursive quick analysis + AI commit analysis to check for dangerous dependencies.
It rests on the `/supplychain/deep-analysis` and is made to be ran up to ten times a day. This means that accuracy is more important than speed. Since recursiveness is part of this module's process, when creating dependency lists, they must be in a hierarchy. It must always be retrievable what dependencies the API endpoint originally received.

#### Input
- One or more lockfiles
#### Output
- A JSON of ALL flagged packages, in a hierarchy

The pipeline of this API endpoint needs to look like this:
1. A lockfile, or a batch of them, is received
2. The lockfile gets parsed into the dependencies it contains and their versions (use existing code, this has already been implemented)
3. A list of ALL dependencies (even dependencies' dependencies) is generated. Dependencies must not repeat in this list, but same dependency, different version is allowed. All dependencies' dependencies must be traceable back to where they're originally mentioned, even when they're mentioned multiple times, then they must contain info of all previous mentions.
4. Quick analysis is run on all dependencies.
5. Dependencies that DO NOT pass quick analysis (their status is flagged as rejected) are added to a list of failed dependencies. The threshold for rejection is WarningLevel::Critical. High, Medium, Low, and Safe all count as passing. If a dependency has a transitive dependency that failed, both are added to the output, but the transitive dependency appears lower in the hierarchy. Failed top-level packages do NOT proceed to steps 7-10 (git URL lookup, commit fetching, AI analysis, mapping). They appear in the final JSON with their quick analysis results only.
6. Using get_dependency_git_url.rs, find git URLs for packages at the top of the hierarchy that passed quick analysis. Support multiple hosting platforms: GitHub (primary), GitLab, Bitbucket, and self-hosted (Gitea etc.). Accept hosting tokens via environment variables (GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_TOKEN).
    - If a package returns no git URL, it is not classified as failed. It continues with its score from quick analysis, but with a notice that no git repo was found.
    - Deduplicate by unique git URL — if multiple packages share the same repository (monorepo), fetch commits only once for that URL. The analysis result applies to all packages from that repo.
7. For each unique git URL from step 6, fetch the last 10 commits along with their diffs. If a module allows you to fetch commits+diffs via a single API call, prefer that. Otherwise, fetch the commit list first, then fetch each commit's diff individually. Respect rate limits for each hosting platform. Implement TTL-based caching so that the same git URL's commits are not re-fetched within the cache window (configurable, default 1 hour).
8. Using universal_llm_comms.rs, launch AI agents in parallel (max 15 running at once) to analyze commits. Each agent analyzes ONE commit + its diff at a time (per-commit analysis, NOT batch). For each commit, use the following prompt:

```
You are a cybersecurity agent analyzing a single code commit for supply chain compromise.

Focus on these suspicious patterns:
- Obfuscated/minified/encoded code (base64, hex, eval(), string encoding)
- New network calls (fetch, curl, request, post) to unfamiliar hosts/IPs
- Modified install scripts (postinstall, build, setup, preinstall)
- Changed repository URLs or download URLs in the code
- Code reading environment variables, config files, or credentials
- Unexpected binary blobs or large encoded strings added
- Backdoored imports or modified require/import paths
- Suspicious file writes to system directories

Ignore: version bumps in metadata, whitespace-only changes, lockfile-only changes, README/doc updates, dependency version bumps without code changes.

Commit: {commit_hash}
Author: {author}
Date: {date}
Message: {commit_message}
Diff:
{diff}

Respond with EXACTLY this JSON — no markdown fences, no explanatory text, exactly this structure:
{"verdict": "allow", "confidence": 1.0, "reasons": [], "suspicious_patterns": []}

Verdict must be one of: "allow", "suspicious", "malicious"
Confidence must be a float 0.0-1.0
Reasons is an array of strings explaining the verdict
Suspicious_patterns is an array of detected pattern names (empty if allow)
```

If an LLM response cannot be parsed as valid JSON, retry once. If it still fails, mark that commit as "uncertain" and continue.
9. The per-commit analysis responses are collected, parsed, and mapped to their respective package. For each package, aggregate the per-commit verdicts: if ANY commit is "malicious", the package verdict is "malicious". If any are "suspicious" and none are "malicious", the package verdict is "suspicious". Otherwise "allow".
10. The JSON, containing a list of ALL flagged packages in a hierarchy, is sent back using the following schema:

```json
{
  "analysis_timestamp": "2026-05-16T12:00:00Z",
  "lockfile_source": "original_filename.ext",
  "summary": {
    "total_packages": 120,
    "flagged": 3,
    "threshold": "Critical",
    "cache_hits": 2,
    "api_calls_made": 15
  },
  "tree": [
    {
      "name": "express",
      "version": "4.18.2",
      "ecosystem": "npm",
      "quick_analysis": {
        "verdict": "pass",
        "warning_level": "high",
        "issues": ["CVE-2023-1234: DoS vulnerability"]
      },
      "git_url": "https://github.com/expressjs/express",
      "hosting_platform": "github",
      "commit_analysis": {
        "verdict": "allow",
        "confidence": 0.95,
        "reasons": ["No suspicious changes detected"],
        "commits_analyzed": 10,
        "commit_details": [
          {
            "hash": "abc123...",
            "verdict": "allow",
            "confidence": 0.95,
            "reasons": []
          }
        ]
      },
      "children": [
        {
          "name": "body-parser",
          "version": "1.20.1",
          "ecosystem": "npm",
          "quick_analysis": {
            "verdict": "rejected",
            "warning_level": "critical",
            "issues": ["Known CVE-2023-5678: Remote code execution"]
          },
          "git_url": null,
          "no_git_url_notice": true,
          "commit_analysis": null,
          "children": []
        }
      ]
    }
  ]
}
```

## Operational Notes

- **Caching**: Use TTL-based caching for git URL lookups and commit fetch results. Default TTL: 1 hour. Cache key: `{hosting_platform}:{owner/repo}`. This avoids redundant API calls across the 10x/day runs.
- **Rate limiting**: Respect per-platform rate limits. GitHub: 5000 req/hr (authenticated via GITHUB_TOKEN). GitLab: check rate limit headers. Implement exponential backoff (1s, 2s, 4s, 8s) on 429 responses.
- **Diff size**: Truncate any single diff at 100KB before sending to LLM. Log truncation events.
- **Timeouts**: Git URL lookup: 10s per package. Commit fetch: 30s per repo. LLM inference: 120s per call.
- **Error handling**: If any step fails for a specific package, mark that package's analysis with an error field and continue processing remaining packages. Do not fail the entire pipeline for a single package failure.

---
Snippets: 
 - Get last 10 commits:
    - ```bash
    curl -H "Accept: application/vnd.github+json" \
     "https://api.github.com/repos/OWNER/REPO/commits?per_page=10"
    ```
 - Get specific commit diff:
    - ```bash
    curl -H "Accept: application/vnd.github.v3.diff" \
     "https://api.github.com/repos/OWNER/REPO/commits/COMMIT_HASH"
    ```
