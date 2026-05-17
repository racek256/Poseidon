//! Performance tracking for request metrics.
//! Tracks request timing and calculates statistics.
//! Only active when interactive mode is enabled.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Thread-safe performance trackers for monitoring request metrics.
/// Only used when interactive mode is enabled.
pub struct PerformanceTrackers {
    /// Total number of requests processed
    pub request_count: AtomicU64,
    /// Total time spent on requests in milliseconds
    pub total_request_time_ms: AtomicU64,
    /// Average delay per request in milliseconds
    pub avg_delay_ms: f64,
    /// Messages/requests per second
    pub msgs_per_second: f64,
    /// Timestamp of the last request start
    pub last_request_time: Instant,
    /// Timestamp when tracking started
    pub start_time: Instant,
}

impl PerformanceTrackers {
    /// Creates a new PerformanceTrackers instance with all counters reset.
    pub fn new() -> Self {
        Self {
            request_count: AtomicU64::new(0),
            total_request_time_ms: AtomicU64::new(0),
            avg_delay_ms: 0.0,
            msgs_per_second: 0.0,
            last_request_time: Instant::now(),
            start_time: Instant::now(),
        }
    }

    /// Records the start of a new request.
    pub fn record_request_start(&mut self) {
        self.last_request_time = Instant::now();
    }

    /// Records the end of a request and updates metrics.
    /// Call this after `record_request_start` with the request duration.
    pub fn record_request_end(&mut self, duration: Duration) {
        let elapsed_ms = duration.as_millis() as u64;

        // Update total request time
        self.total_request_time_ms
            .fetch_add(elapsed_ms, Ordering::Relaxed);

        // Increment request count
        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Calculate average delay
        let count = self.request_count.load(Ordering::Relaxed);
        let total_time = self.total_request_time_ms.load(Ordering::Relaxed);
        if count > 0 {
            self.avg_delay_ms = total_time as f64 / count as f64;
        }

        // Calculate messages per second
        let total_elapsed = self.start_time.elapsed().as_secs_f64();
        if total_elapsed > 0.0 {
            self.msgs_per_second = count as f64 / total_elapsed;
        }
    }

    /// Records the end time relative to the last request start.
    pub fn record_request_completed(&mut self) {
        let duration = self.last_request_time.elapsed();
        self.record_request_end(duration);
    }

    /// Returns the total number of requests processed.
    pub fn get_request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Returns the total request time in milliseconds.
    pub fn get_total_request_time_ms(&self) -> u64 {
        self.total_request_time_ms.load(Ordering::Relaxed)
    }

    /// Returns the average delay per request in milliseconds.
    pub fn get_avg_delay_ms(&self) -> f64 {
        self.avg_delay_ms
    }

    /// Returns the messages per second rate.
    pub fn get_msgs_per_second(&self) -> f64 {
        self.msgs_per_second
    }

    /// Returns the elapsed time since tracking started.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Returns formatted uptime string (HH:MM:SS).
    pub fn uptime_string(&self) -> String {
        let elapsed = self.elapsed();
        let hours = elapsed.as_secs() / 3600;
        let minutes = (elapsed.as_secs() % 3600) / 60;
        let seconds = elapsed.as_secs() % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }

    /// Resets all trackers to initial state.
    /// Does not restart the start_time, just resets counters.
    pub fn reset(&mut self) {
        self.request_count.store(0, Ordering::Relaxed);
        self.total_request_time_ms.store(0, Ordering::Relaxed);
        self.avg_delay_ms = 0.0;
        self.msgs_per_second = 0.0;
    }

    /// Full reset including start time.
    pub fn hard_reset(&mut self) {
        self.reset();
        self.start_time = Instant::now();
        self.last_request_time = Instant::now();
    }
}

impl Default for PerformanceTrackers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_trackers() {
        let trackers = PerformanceTrackers::new();
        assert_eq!(trackers.get_request_count(), 0);
        assert_eq!(trackers.get_avg_delay_ms(), 0.0);
        assert_eq!(trackers.get_msgs_per_second(), 0.0);
    }

    #[test]
    fn test_record_request() {
        let mut trackers = PerformanceTrackers::new();
        trackers.record_request_start();
        std::thread::sleep(Duration::from_millis(10));
        trackers.record_request_completed();

        assert_eq!(trackers.get_request_count(), 1);
        assert!(trackers.get_avg_delay_ms() >= 10.0);
    }

    #[test]
    fn test_multiple_requests() {
        let mut trackers = PerformanceTrackers::new();

        for _ in 0..5 {
            trackers.record_request_start();
            trackers.record_request_completed();
        }

        assert_eq!(trackers.get_request_count(), 5);
    }

    #[test]
    fn test_reset() {
        let mut trackers = PerformanceTrackers::new();
        trackers.record_request_start();
        trackers.record_request_completed();
        trackers.reset();

        assert_eq!(trackers.get_request_count(), 0);
        assert_eq!(trackers.get_avg_delay_ms(), 0.0);
    }
}
