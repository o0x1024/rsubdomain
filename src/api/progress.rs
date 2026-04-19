use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BruteForceProgressPhase {
    SendingQueries,
    WaitingForResponses,
    Completed,
}

#[derive(Debug, Clone)]
pub struct BruteForceProgress {
    pub phase: BruteForceProgressPhase,
    pub sent_queries: usize,
    pub total_queries: usize,
    pub discovered_domains: usize,
    pub current_target: Option<String>,
}

pub type ProgressCallback = Arc<dyn Fn(BruteForceProgress) + Send + Sync>;
