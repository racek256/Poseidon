use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub date: String,
    pub message: String,
    pub diff: String,
}

#[derive(Debug)]
pub struct AnalysisCache {
    git_url_cache: Mutex<HashMap<String, (Option<String>, Instant)>>,
    commit_cache: Mutex<HashMap<String, (Vec<CommitInfo>, Instant)>>,
    ttl: Duration,
    hits: Mutex<u64>,
    misses: Mutex<u64>,
}

pub const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

impl AnalysisCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            git_url_cache: Mutex::new(HashMap::new()),
            commit_cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
            hits: Mutex::new(0),
            misses: Mutex::new(0),
        }
    }

    pub fn get_git_url(&self, key: &str) -> Option<Option<String>> {
        let mut cache = self.git_url_cache.lock().unwrap();
        if let Some((url, instant)) = cache.get(key) {
            if instant.elapsed() <= self.ttl {
                *self.hits.lock().unwrap() += 1;
                return Some(url.clone());
            } else {
                cache.remove(key);
            }
        }
        *self.misses.lock().unwrap() += 1;
        None
    }

    pub fn set_git_url(&self, key: &str, url: Option<String>) {
        let mut cache = self.git_url_cache.lock().unwrap();
        cache.insert(key.to_string(), (url, Instant::now()));
    }

    pub fn get_commits(&self, key: &str) -> Option<Vec<CommitInfo>> {
        let mut cache = self.commit_cache.lock().unwrap();
        if let Some((commits, instant)) = cache.get(key) {
            if instant.elapsed() <= self.ttl {
                *self.hits.lock().unwrap() += 1;
                return Some(commits.clone());
            } else {
                cache.remove(key);
            }
        }
        *self.misses.lock().unwrap() += 1;
        None
    }

    pub fn set_commits(&self, key: &str, commits: Vec<CommitInfo>) {
        let mut cache = self.commit_cache.lock().unwrap();
        cache.insert(key.to_string(), (commits, Instant::now()));
    }

    pub fn len(&self) -> usize {
        let git_len = self.git_url_cache.lock().unwrap().len();
        let commit_len = self.commit_cache.lock().unwrap().len();
        git_len + commit_len
    }

    pub fn hit_count(&self) -> u64 {
        *self.hits.lock().unwrap()
    }

    pub fn miss_count(&self) -> u64 {
        *self.misses.lock().unwrap()
    }
}

impl Default for AnalysisCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_TTL_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cache() {
        let cache = AnalysisCache::new(1800);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.hit_count(), 0);
        assert_eq!(cache.miss_count(), 0);
    }

    #[test]
    fn test_default_cache() {
        let cache = AnalysisCache::default();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_git_url_caching() {
        let cache = AnalysisCache::new(3600);

        assert_eq!(cache.get_git_url("npm:lodash"), None);
        assert_eq!(cache.miss_count(), 1);

        cache.set_git_url("npm:lodash", Some("https://github.com/lodash/lodash".to_string()));

        let result = cache.get_git_url("npm:lodash");
        assert_eq!(result, Some(Some("https://github.com/lodash/lodash".to_string())));
        assert_eq!(cache.hit_count(), 1);
    }

    #[test]
    fn test_negative_caching() {
        let cache = AnalysisCache::new(3600);

        cache.set_git_url("npm:nonexistent", None);

        let result = cache.get_git_url("npm:nonexistent");
        assert_eq!(result, Some(None));
        assert_eq!(cache.hit_count(), 1);
    }

    #[test]
    fn test_commit_caching() {
        let cache = AnalysisCache::new(3600);

        let commits = vec![
            CommitInfo {
                hash: "abc123".to_string(),
                author: "Test Author".to_string(),
                date: "2024-01-01".to_string(),
                message: "Test commit".to_string(),
                diff: "diff content".to_string(),
            },
        ];

        cache.set_commits("github:lodash/lodash", commits.clone());

        let result = cache.get_commits("github:lodash/lodash");
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(cache.hit_count(), 1);
    }

    #[test]
    fn test_ttl_expiry() {
        let cache = AnalysisCache::new(1);

        cache.set_git_url("npm:test", Some("https://example.com".to_string()));
        assert_eq!(cache.get_git_url("npm:test"), Some(Some("https://example.com".to_string())));

        std::thread::sleep(Duration::from_secs(2));

        assert_eq!(cache.get_git_url("npm:test"), None);
        assert_eq!(cache.miss_count(), 1);
    }

    #[test]
    fn test_len() {
        let cache = AnalysisCache::new(3600);

        assert_eq!(cache.len(), 0);

        cache.set_git_url("npm:pkg1", Some("url1".to_string()));
        assert_eq!(cache.len(), 1);

        cache.set_git_url("npm:pkg2", None);
        assert_eq!(cache.len(), 2);

        let commits = vec![CommitInfo {
            hash: "abc".to_string(),
            author: "auth".to_string(),
            date: "date".to_string(),
            message: "msg".to_string(),
            diff: "diff".to_string(),
        }];
        cache.set_commits("github:owner/repo", commits);
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_cache_basic_git_url() {
        let cache = AnalysisCache::new(3600);
        assert_eq!(cache.hit_count(), 0);
        assert_eq!(cache.miss_count(), 0);

        // Should miss on first lookup
        assert_eq!(cache.get_git_url("npm:express"), None);
        assert_eq!(cache.miss_count(), 1);

        // Set and retrieve
        cache.set_git_url("npm:express", Some("https://github.com/expressjs/express".to_string()));
        let cached = cache.get_git_url("npm:express");
        assert_eq!(cached, Some(Some("https://github.com/expressjs/express".to_string())));
        assert_eq!(cache.hit_count(), 1);
    }

    #[test]
    fn test_cache_negative_caching() {
        let cache = AnalysisCache::new(3600);

        // Store None (negative cache — package has no git URL)
        cache.set_git_url("pypi:unknown-pkg-12345", None);
        let cached = cache.get_git_url("pypi:unknown-pkg-12345");
        assert_eq!(cached, Some(None));
    }

    #[test]
    fn test_cache_multiple_entries() {
        let cache = AnalysisCache::new(3600);
        cache.set_git_url("npm:a", Some("https://github.com/a/a.git".to_string()));
        cache.set_git_url("npm:b", Some("https://github.com/b/b.git".to_string()));
        assert_eq!(cache.get_git_url("npm:a"), Some(Some("https://github.com/a/a.git".to_string())));
        assert_eq!(cache.get_git_url("npm:b"), Some(Some("https://github.com/b/b.git".to_string())));
    }

    #[test]
    fn test_cache_commit_info() {
        let cache = AnalysisCache::new(3600);
        let commits = vec![
            CommitInfo {
                hash: "abc123".to_string(),
                author: "test".to_string(),
                date: "2024-01-01".to_string(),
                message: "test commit".to_string(),
                diff: "some diff".to_string(),
            }
        ];

        assert!(cache.get_commits("github:expressjs/express").is_none());
        cache.set_commits("github:expressjs/express", commits.clone());
        let cached = cache.get_commits("github:expressjs/express");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);
    }

    #[test]
    fn test_cache_len_and_counts() {
        let cache = AnalysisCache::new(3600);
        assert_eq!(cache.len(), 0);
        cache.set_git_url("test:pkg", None);
        assert_eq!(cache.len(), 1);
        cache.set_commits("test:repo", vec![]);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.hit_count(), 0);
        assert_eq!(cache.miss_count(), 0);
    }

    #[test]
    fn test_default_ttl() {
        let cache = AnalysisCache::default();
        cache.set_git_url("test:key", Some("https://example.com".to_string()));
        let result = cache.get_git_url("test:key");
        assert_eq!(result, Some(Some("https://example.com".to_string())));
    }
}