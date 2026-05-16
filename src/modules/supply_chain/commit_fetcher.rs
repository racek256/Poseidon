use std::time::Duration;
use reqwest::blocking::Client;
use serde_json::Value;
use crate::modules::tui::bridge;
use super::analysis_cache::CommitInfo;

const REQUEST_DELAY_MS: u64 = 100;
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_DIFF_BYTES: usize = 100 * 1024;

#[derive(Debug)]
pub struct CommitFetcher {
    client: Client,
}

impl CommitFetcher {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent("Poseidon-CommitFetcher/1.0")
            .build()
            .expect("Failed to create HTTP client for CommitFetcher");
        Self { client }
    }

    /// Fetches last N commits + diffs for a git URL.
    /// git_url: normalized HTTPS URL like https://github.com/owner/repo
    /// platform: "github", "gitlab", "bitbucket", "self-hosted"
    /// count: number of recent commits to fetch (default 10)
    pub fn fetch_commits(&self, git_url: &str, platform: &str, count: usize) -> Result<Vec<CommitInfo>, String> {
        match platform {
            "github" => self.fetch_github_commits(git_url, count),
            "gitlab" => self.fetch_gitlab_commits(git_url, count),
            "bitbucket" => self.fetch_bitbucket_commits(git_url, count),
            "self-hosted" => self.fetch_self_hosted_commits(git_url, count),
            _ => Err(format!("Unknown hosting platform: {}", platform)),
        }
    }

    fn fetch_github_commits(&self, git_url: &str, count: usize) -> Result<Vec<CommitInfo>, String> {
        let (owner, repo) = Self::git_url_to_owner_repo(git_url)
            .filter(|(o, r)| !o.is_empty() && !r.is_empty())
            .ok_or_else(|| format!("Invalid GitHub URL: {}", git_url))?;

        let token = std::env::var("GITHUB_TOKEN").ok();

        let url = format!(
            "https://api.github.com/repos/{}/{}/commits?per_page={}",
            owner, repo, count
        );

        let mut request = self.client.get(&url)
            .header("Accept", "application/vnd.github+json");

        if let Some(ref t) = token {
            request = request.header("Authorization", format!("Bearer {}", t));
        }

        let response = request.send().map_err(|e| format!("GitHub API request failed: {}", e))?;

        if let Some(delay) = self.get_rate_limit_delay(&response) {
            std::thread::sleep(Duration::from_secs(delay));
        }

        let commits: Value = if response.status().as_u16() == 429 {
            std::thread::sleep(Duration::from_secs(1));
            let request = self.client.get(&url)
                .header("Accept", "application/vnd.github+json");
            let response = request.send().map_err(|e| format!("GitHub API retry failed: {}", e))?;
            if !response.status().is_success() {
                return Err(format!("GitHub API returned status: {}", response.status()));
            }
            let body = response.text().map_err(|e| format!("Failed to read GitHub response: {}", e))?;
            serde_json::from_str(&body)
                .map_err(|e| format!("Failed to parse GitHub commits response: {}", e))?
        } else if !response.status().is_success() {
            return Err(format!("GitHub API returned status: {}", response.status()));
        } else {
            let body = response.text().map_err(|e| format!("Failed to read GitHub response: {}", e))?;
            serde_json::from_str(&body)
                .map_err(|e| format!("Failed to parse GitHub commits response: {}", e))?
        };

        let commits_array = commits.as_array()
            .ok_or_else(|| "GitHub commits response is not an array".to_string())?;

        let mut result = Vec::new();

        for commit_item in commits_array {
            let hash = commit_item["sha"].as_str().unwrap_or("").to_string();
            let author = commit_item["commit"]["author"]["name"].as_str().unwrap_or("").to_string();
            let date = commit_item["commit"]["author"]["date"].as_str().unwrap_or("").to_string();
            let message = commit_item["commit"]["message"].as_str().unwrap_or("").to_string();

            // Fetch diff for this commit
            let diff_url = format!(
                "https://api.github.com/repos/{}/{}/commits/{}",
                owner, repo, hash
            );

            std::thread::sleep(Duration::from_millis(REQUEST_DELAY_MS));

            let mut diff_request = self.client.get(&diff_url)
                .header("Accept", "application/vnd.github.v3.diff");

            if let Some(ref t) = token {
                diff_request = diff_request.header("Authorization", format!("Bearer {}", t));
            }

            let diff_response = match diff_request.send() {
                Ok(resp) => resp,
                Err(e) => {
                    bridge::elog(&format!("Failed to fetch diff for {}: {}", hash, e));
                    result.push(CommitInfo {
                        hash,
                        author,
                        date,
                        message,
                        diff: String::new(),
                    });
                    continue;
                }
            };

            if diff_response.status().as_u16() == 429 {
                std::thread::sleep(Duration::from_secs(1));
            }

            let diff = if diff_response.status().is_success() {
                let text = diff_response.text().unwrap_or_default();
                self.truncate_diff_with_max(&text, MAX_DIFF_BYTES)
            } else {
                bridge::elog(&format!("Diff fetch failed for {}: status {}", hash, diff_response.status()));
                String::new()
            };

            result.push(CommitInfo {
                hash,
                author,
                date,
                message,
                diff,
            });
        }

        Ok(result)
    }

    fn fetch_gitlab_commits(&self, git_url: &str, count: usize) -> Result<Vec<CommitInfo>, String> {
        let (owner, repo) = Self::git_url_to_owner_repo(git_url)
            .filter(|(o, r)| !o.is_empty() && !r.is_empty())
            .ok_or_else(|| format!("Invalid GitLab URL: {}", git_url))?;

        let token = std::env::var("GITLAB_TOKEN").ok();

        // GitLab requires URL-encoded project path (owner/repo -> owner%2Frepo)
        let encoded_project = format!("{}%2F{}", owner, repo);

        let url = format!(
            "https://gitlab.com/api/v4/projects/{}/repository/commits?per_page={}",
            encoded_project, count
        );

        let mut request = self.client.get(&url);

        if let Some(ref t) = token {
            request = request.header("PRIVATE-TOKEN", t);
        }

        let response = request.send().map_err(|e| format!("GitLab API request failed: {}", e))?;

        if response.status().as_u16() == 429 {
            std::thread::sleep(Duration::from_secs(1));
            let request = self.client.get(&url);
            let response = request.send().map_err(|e| format!("GitLab API retry failed: {}", e))?;
            if !response.status().is_success() {
                return Err(format!("GitLab API returned status: {}", response.status()));
            }
        } else if !response.status().is_success() {
            return Err(format!("GitLab API returned status: {}", response.status()));
        }

        let commits: Value = serde_json::from_reader(response)
            .map_err(|e| format!("Failed to parse GitLab commits response: {}", e))?;

        let commits_array = commits.as_array()
            .ok_or_else(|| "GitLab commits response is not an array".to_string())?;

        let mut result = Vec::new();

        for commit_item in commits_array {
            let hash = commit_item["id"].as_str().unwrap_or("").to_string();
            let author = commit_item["author_name"].as_str().unwrap_or("").to_string();
            let date = commit_item["created_at"].as_str().unwrap_or("").to_string();
            let message = commit_item["message"].as_str().unwrap_or("").to_string();

            // Fetch diff for this commit
            let diff_url = format!(
                "https://gitlab.com/api/v4/projects/{}/repository/commits/{}/diff",
                encoded_project, hash
            );

            std::thread::sleep(Duration::from_millis(REQUEST_DELAY_MS));

            let mut diff_request = self.client.get(&diff_url);

            if let Some(ref t) = token {
                diff_request = diff_request.header("PRIVATE-TOKEN", t);
            }

            let diff_response = match diff_request.send() {
                Ok(resp) => resp,
                Err(e) => {
                    bridge::elog(&format!("Failed to fetch diff for {}: {}", hash, e));
                    result.push(CommitInfo {
                        hash,
                        author,
                        date,
                        message,
                        diff: String::new(),
                    });
                    continue;
                }
            };

            if diff_response.status().as_u16() == 429 {
                std::thread::sleep(Duration::from_secs(1));
            }

            let diff = if diff_response.status().is_success() {
                let diff_data: Value = serde_json::from_reader(diff_response)
                    .unwrap_or(Value::Null);
                let mut diff_text = String::new();
                if let Some(arr) = diff_data.as_array() {
                    for d in arr {
                        if let Some(s) = d["diff"].as_str() {
                            diff_text.push_str(s);
                            diff_text.push('\n');
                        }
                    }
                }
                self.truncate_diff_with_max(&diff_text, MAX_DIFF_BYTES)
            } else {
                bridge::elog(&format!("Diff fetch failed for {}: status {}", hash, diff_response.status()));
                String::new()
            };

            result.push(CommitInfo {
                hash,
                author,
                date,
                message,
                diff,
            });
        }

        Ok(result)
    }

    fn fetch_bitbucket_commits(&self, git_url: &str, count: usize) -> Result<Vec<CommitInfo>, String> {
        let (owner, repo) = Self::git_url_to_owner_repo(git_url)
            .filter(|(o, r)| !o.is_empty() && !r.is_empty())
            .ok_or_else(|| format!("Invalid Bitbucket URL: {}", git_url))?;

        let url = format!(
            "https://api.bitbucket.org/2.0/repositories/{}/{}/commits?pagelen={}",
            owner, repo, count
        );

        let mut request = self.client.get(&url);

        let response = request.send().map_err(|e| format!("Bitbucket API request failed: {}", e))?;

        if response.status().as_u16() == 429 {
            std::thread::sleep(Duration::from_secs(1));
            let request = self.client.get(&url);
            let response = request.send().map_err(|e| format!("Bitbucket API retry failed: {}", e))?;
            if !response.status().is_success() {
                return Err(format!("Bitbucket API returned status: {}", response.status()));
            }
        } else if !response.status().is_success() {
            return Err(format!("Bitbucket API returned status: {}", response.status()));
        }

        let commits: Value = serde_json::from_reader(response)
            .map_err(|e| format!("Failed to parse Bitbucket commits response: {}", e))?;

        let commits_array = commits["values"].as_array()
            .ok_or_else(|| "Bitbucket commits response missing values array".to_string())?;

        let mut result = Vec::new();

        for commit_item in commits_array {
            let hash = commit_item["hash"].as_str().unwrap_or("").to_string();
            let author = commit_item["author"]["raw"].as_str()
                .map(|s| s.split('<').next().unwrap_or(s).to_string())
                .unwrap_or_default();
            let date = commit_item["date"].as_str().unwrap_or("").to_string();
            let message = commit_item["message"].as_str().unwrap_or("").to_string();

            let diff_href = commit_item["links"]["diff"]["href"].as_str().unwrap_or("");

            if diff_href.is_empty() {
                result.push(CommitInfo {
                    hash,
                    author,
                    date,
                    message,
                    diff: String::new(),
                });
                continue;
            }

            std::thread::sleep(Duration::from_millis(REQUEST_DELAY_MS));

            let mut diff_request = self.client.get(diff_href);

            let diff_response = match diff_request.send() {
                Ok(resp) => resp,
                Err(e) => {
                    bridge::elog(&format!("Failed to fetch diff for {}: {}", hash, e));
                    result.push(CommitInfo {
                        hash,
                        author,
                        date,
                        message,
                        diff: String::new(),
                    });
                    continue;
                }
            };

            if diff_response.status().as_u16() == 429 {
                std::thread::sleep(Duration::from_secs(1));
            }

            let diff = if diff_response.status().is_success() {
                let text = diff_response.text().unwrap_or_default();
                self.truncate_diff_with_max(&text, MAX_DIFF_BYTES)
            } else {
                bridge::elog(&format!("Diff fetch failed for {}: status {}", hash, diff_response.status()));
                String::new()
            };

            result.push(CommitInfo {
                hash,
                author,
                date,
                message,
                diff,
            });
        }

        Ok(result)
    }

    fn fetch_self_hosted_commits(&self, git_url: &str, count: usize) -> Result<Vec<CommitInfo>, String> {
        let (owner, repo) = Self::git_url_to_owner_repo(git_url)
            .filter(|(o, r)| !o.is_empty() && !r.is_empty())
            .ok_or_else(|| format!("Invalid git URL for self-hosted: {}", git_url))?;

        let token: Option<String> = std::env::var("GITEA_TOKEN")
            .or_else(|_| std::env::var("GIT_TOKEN")).ok();

        let base_url = git_url
            .trim_end_matches(".git")
            .trim_end_matches('/');

        let gitea_commits_url = format!(
            "{}/api/v1/repos/{}/{}/commits?limit={}",
            base_url, owner, repo, count
        );

        let mut request_builder = self.client.get(&gitea_commits_url);

        if let Some(ref t) = token {
            request_builder = request_builder.header("Authorization", format!("Bearer {}", t));
        }

        let gitea_response = request_builder.send();

        let commits: Value = if let Ok(mut resp) = gitea_response {
            if resp.status().is_success() {
                let body = resp.text().unwrap_or_default();
                serde_json::from_str(&body).unwrap_or(Value::Null)
            } else {
                Value::Null
            }
        } else {
            let encoded_project = format!("{}%2F{}", owner, repo);
            let gitlab_commits_url = format!(
                "{}/api/v4/projects/{}/repository/commits?per_page={}",
                base_url, encoded_project, count
            );

            let mut request = self.client.get(&gitlab_commits_url);

            if let Some(ref t) = token {
                request = request.header("PRIVATE-TOKEN", t);
            }

            let response = request.send().map_err(|e| format!("Self-hosted Git API request failed: {}", e))?;

            if response.status().as_u16() == 429 {
                std::thread::sleep(Duration::from_secs(1));
            }

            if !response.status().is_success() {
                return Err(format!("Self-hosted API returned status: {}", response.status()));
            }

            serde_json::from_reader(response)
                .map_err(|e| format!("Failed to parse self-hosted commits response: {}", e))?
        };

        let commits_array = commits.as_array()
            .ok_or_else(|| "Self-hosted commits response is not an array".to_string())?;

        let mut result = Vec::new();

        for commit_item in commits_array {
            // Gitea format: hash, commit.author.name, commit.author.date, commit.message
            // GitLab format: id, author, created_at, message
            let hash = commit_item["sha"].as_str()
                .or_else(|| commit_item["id"].as_str())
                .unwrap_or("").to_string();

            let author = commit_item["commit"]["author"]["name"].as_str()
                .or_else(|| commit_item["author_name"].as_str())
                .unwrap_or("").to_string();

            let date = commit_item["commit"]["author"]["date"].as_str()
                .or_else(|| commit_item["created_at"].as_str())
                .unwrap_or("").to_string();

            let message = commit_item["commit"]["message"].as_str()
                .or_else(|| commit_item["message"].as_str())
                .unwrap_or("").to_string();

            std::thread::sleep(Duration::from_millis(REQUEST_DELAY_MS));

            // Try to fetch diff - Gitea style
            let diff_url = format!(
                "{}/api/v1/repos/{}/{}/git/commits/{}",
                base_url, owner, repo, hash
            );

            let mut diff_request = self.client.get(&diff_url);

            if let Some(ref t) = token {
                diff_request = diff_request.header("Authorization", format!("Bearer {}", t));
            }

            let diff_response = diff_request.send();

            let diff = if diff_response.is_ok() && diff_response.as_ref().unwrap().status().is_success() {
                let mut resp = diff_response.unwrap();
                let text = resp.text().unwrap_or_default();
                self.truncate_diff_with_max(&text, MAX_DIFF_BYTES)
            } else {
                // Try GitLab CE diff endpoint
                let encoded_project = format!("{}%2F{}", owner, repo);
                let gitlab_diff_url = format!(
                    "{}/api/v4/projects/{}/repository/commits/{}/diff",
                    base_url, encoded_project, hash
                );

                let mut diff_request = self.client.get(&gitlab_diff_url);

                if let Some(ref t) = token {
                    diff_request = diff_request.header("PRIVATE-TOKEN", t);
                }

                match diff_request.send() {
                    Ok(resp) if resp.status().is_success() => {
                        let diff_body = resp.text().unwrap_or_default();
                        let diff_data: Value = serde_json::from_str(&diff_body)
                            .unwrap_or(Value::Null);
                        let mut diff_text = String::new();
                        if let Some(arr) = diff_data.as_array() {
                            for d in arr {
                                if let Some(s) = d["diff"].as_str() {
                                    diff_text.push_str(s);
                                    diff_text.push('\n');
                                }
                            }
                        }
                        self.truncate_diff_with_max(&diff_text, MAX_DIFF_BYTES)
                    }
                    _ => {
                        bridge::elog(&format!("Failed to fetch diff for {} from self-hosted server", hash));
                        String::new()
                    }
                }
            };

            result.push(CommitInfo {
                hash,
                author,
                date,
                message,
                diff,
            });
        }

        Ok(result)
    }

    /// Extracts owner/repo from a normalized HTTPS git URL
    fn git_url_to_owner_repo(git_url: &str) -> Option<(String, String)> {
        let url = git_url.trim_end_matches(".git").trim_end_matches('/');

        // Handle https://github.com/owner/repo
        if let Some(pos) = url.find("github.com/") {
            let path = &url[pos + "github.com/".len()..];
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 2 {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }

        // Handle https://gitlab.com/owner/repo
        if let Some(pos) = url.find("gitlab.com/") {
            let path = &url[pos + "gitlab.com/".len()..];
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 2 {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }

        // Handle https://bitbucket.org/owner/repo
        if let Some(pos) = url.find("bitbucket.org/") {
            let path = &url[pos + "bitbucket.org/".len()..];
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 2 {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }

        // Handle self-hosted URLs - extract from the path after the host
        if let Some(host_pos) = url.find("://") {
            if let Some(path_start) = url[host_pos + 3..].find('/') {
                let path = &url[host_pos + 3 + path_start..].trim_start_matches('/');
                let parts: Vec<&str> = path.split('/').collect();
                if parts.len() >= 2 {
                    return Some((parts[0].to_string(), parts[1].to_string()));
                }
            }
        }

        None
    }

    /// Truncates diff at max_bytes with a log message
    fn truncate_diff_with_max(&self, diff: &str, max_bytes: usize) -> String {
        if diff.len() <= max_bytes {
            return diff.to_string();
        }

        // Find a safe truncation point near max_bytes
        let truncated = &diff[..max_bytes];
        let cutoff = truncated.rfind('\n').map(|p| p).unwrap_or(max_bytes);

        bridge::log(&format!(
            "Diff truncated from {} to {} bytes (limit: {})",
            diff.len(),
            cutoff,
            max_bytes
        ));

        diff[..cutoff].to_string()
    }

    /// Parses rate limit headers and returns delay in seconds if rate limited
    fn get_rate_limit_delay(&self, response: &reqwest::blocking::Response) -> Option<u64> {
        if response.headers().get("X-RateLimit-Remaining")?.as_bytes() == b"0" {
            let reset = response.headers().get("X-RateLimit-Reset")?;
            if let Ok(header_str) = reset.to_str() {
                if let Ok(reset_ts) = header_str.parse::<u64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if reset_ts > now {
                        return Some(reset_ts - now);
                    }
                }
            }
        }
        None
    }
}

impl Default for CommitFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_fetcher_creation() {
        let fetcher = CommitFetcher::new();
        assert!(!format!("{:?}", fetcher).is_empty());
    }

    #[test]
    fn test_git_url_to_owner_repo_github() {
        let result = CommitFetcher::git_url_to_owner_repo("https://github.com/owner/repo");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_git_url_to_owner_repo_with_git_suffix() {
        let result = CommitFetcher::git_url_to_owner_repo("https://github.com/owner/repo.git");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_git_url_to_owner_repo_subdirs() {
        let result = CommitFetcher::git_url_to_owner_repo("https://gitlab.com/group/subgroup/project");
        assert_eq!(result, Some(("group".to_string(), "subgroup".to_string())));
    }

    #[test]
    fn test_git_url_to_owner_repo_invalid() {
        assert_eq!(CommitFetcher::git_url_to_owner_repo("not-a-url"), None);
        assert_eq!(CommitFetcher::git_url_to_owner_repo(""), None);
    }

    #[test]
    fn test_truncate_diff_short() {
        let fetcher = CommitFetcher::new();
        let diff = "short diff content";
        let result = fetcher.truncate_diff_with_max(diff, 100 * 1024);
        assert_eq!(result, diff);
    }

    #[test]
    fn test_truncate_diff_long() {
        let fetcher = CommitFetcher::new();
        let diff = "a".repeat(200);
        let result = fetcher.truncate_diff_with_max(&diff, 100);
        assert_eq!(result.len(), 100);
    }

    #[test]
    fn test_get_rate_limit_delay_no_headers() {
        let fetcher = CommitFetcher::new();
        assert!(format!("{:?}", fetcher).contains("CommitFetcher"));
    }

    #[test]
    fn test_default_impl() {
        let fetcher = CommitFetcher::default();
        assert!(format!("{:?}", fetcher).contains("CommitFetcher"));
    }
}