use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
struct ResolverStats {
    srtt_ms: Option<f64>,
    rttvar_ms: f64,
    consecutive_timeouts: u32,
    consecutive_failures: u32,
}

impl ResolverStats {
    fn new() -> Self {
        Self {
            srtt_ms: None,
            rttvar_ms: 0.0,
            consecutive_timeouts: 0,
            consecutive_failures: 0,
        }
    }

    fn score(&self) -> f64 {
        let baseline = self.srtt_ms.unwrap_or(150.0);
        baseline
            + self.rttvar_ms
            + (self.consecutive_timeouts as f64 * 750.0)
            + (self.consecutive_failures as f64 * 500.0)
    }
}

#[derive(Debug, Clone)]
pub struct ResolverHealth {
    stats: HashMap<String, ResolverStats>,
    srtt_ms: Option<f64>,
    rttvar_ms: f64,
}

impl ResolverHealth {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
            srtt_ms: None,
            rttvar_ms: 0.0,
        }
    }

    pub fn choose_resolver(&mut self, resolvers: &[String], routing_key: &str) -> Option<String> {
        if resolvers.is_empty() {
            return None;
        }

        let candidates = resolvers
            .iter()
            .cloned()
            .map(|resolver| {
                let score = self
                    .stats
                    .entry(resolver.clone())
                    .or_insert_with(ResolverStats::new)
                    .score();
                (resolver, score)
            })
            .collect::<Vec<_>>();

        let best_score = candidates
            .iter()
            .map(|(_, score)| *score)
            .reduce(f64::min)?;
        let epsilon = 0.001;
        let mut best_candidates = candidates
            .into_iter()
            .filter(|(_, score)| (*score - best_score).abs() <= epsilon)
            .map(|(resolver, _)| resolver)
            .collect::<Vec<_>>();
        best_candidates.sort();

        let hash_index = stable_hash(routing_key) % best_candidates.len();
        Some(best_candidates[hash_index].clone())
    }

    pub fn record_success(&mut self, resolver: &str, rtt_ms: f64) {
        let stats = self
            .stats
            .entry(resolver.to_string())
            .or_insert_with(ResolverStats::new);
        update_ewma(&mut stats.srtt_ms, &mut stats.rttvar_ms, rtt_ms);
        stats.consecutive_timeouts = 0;
        stats.consecutive_failures = 0;

        update_ewma(&mut self.srtt_ms, &mut self.rttvar_ms, rtt_ms);
    }

    pub fn record_timeout(&mut self, resolver: &str) {
        let stats = self
            .stats
            .entry(resolver.to_string())
            .or_insert_with(ResolverStats::new);
        stats.consecutive_timeouts = stats.consecutive_timeouts.saturating_add(1);
    }

    pub fn record_failure(&mut self, resolver: &str) {
        let stats = self
            .stats
            .entry(resolver.to_string())
            .or_insert_with(ResolverStats::new);
        stats.consecutive_failures = stats.consecutive_failures.saturating_add(1);
    }

    pub fn timeout_seconds(&self, cap_seconds: u64) -> u64 {
        let cap_millis = (cap_seconds.max(1) * 1000) as f64;
        let estimate_ms = match self.srtt_ms {
            Some(srtt) => (srtt + 4.0 * self.rttvar_ms).clamp(1000.0, cap_millis),
            None => cap_millis,
        };
        ((estimate_ms / 1000.0).ceil() as u64).max(1).min(cap_seconds.max(1))
    }
}

impl Default for ResolverHealth {
    fn default() -> Self {
        Self::new()
    }
}

fn update_ewma(srtt_ms: &mut Option<f64>, rttvar_ms: &mut f64, sample_ms: f64) {
    let sample_ms = sample_ms.max(1.0);

    match srtt_ms {
        Some(srtt) => {
            let rttvar = 0.75 * *rttvar_ms + 0.25 * (*srtt - sample_ms).abs();
            let updated_srtt = 0.875 * *srtt + 0.125 * sample_ms;
            *srtt = updated_srtt;
            *rttvar_ms = rttvar;
        }
        None => {
            *srtt_ms = Some(sample_ms);
            *rttvar_ms = sample_ms / 2.0;
        }
    }
}

fn stable_hash(value: &str) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as usize
}

#[cfg(test)]
mod tests {
    use super::ResolverHealth;

    #[test]
    fn prefers_healthier_resolver() {
        let mut health = ResolverHealth::new();
        health.record_success("1.1.1.1", 20.0);
        health.record_timeout("8.8.8.8");

        let chosen = health
            .choose_resolver(&["1.1.1.1".to_string(), "8.8.8.8".to_string()], "www.example.com")
            .unwrap();

        assert_eq!(chosen, "1.1.1.1");
    }

    #[test]
    fn dynamic_timeout_respects_upper_cap() {
        let mut health = ResolverHealth::new();
        health.record_success("1.1.1.1", 1200.0);

        assert_eq!(health.timeout_seconds(1), 1);
        assert!(health.timeout_seconds(10) >= 2);
    }
}
