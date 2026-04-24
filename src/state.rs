//! 线程安全的状态管理模块
//!
//! 这个模块提供了线程安全的状态管理结构，替代原有的全局静态变量。
//! 每个SubdomainBruteEngine实例都有自己独立的状态，确保线程安全。

use crate::handle::{DiscoveredDomain, VerificationResult};
use crate::local_struct::LocalStruct;
use crate::resolver_health::ResolverHealth;
use crate::stack::Stack;
use std::sync::{Arc, Mutex, RwLock};

/// 暴破引擎的状态管理器
///
/// 包含了域名暴破过程中需要的所有状态信息，
/// 每个SubdomainBruteEngine实例都有独立的状态。
#[derive(Debug, Clone)]
pub struct BruteForceState {
    /// 发现的域名列表
    pub discovered_domains: Arc<Mutex<Vec<DiscoveredDomain>>>,
    /// 验证结果列表
    pub verification_results: Arc<Mutex<Vec<VerificationResult>>>,
    /// 本地状态管理
    pub local_status: Arc<RwLock<LocalStruct>>,
    /// 本地栈结构
    pub local_stack: Arc<RwLock<Stack<usize>>>,
    /// DNS 解析器健康状态
    pub resolver_health: Arc<Mutex<ResolverHealth>>,
}

impl BruteForceState {
    /// 创建新的状态管理器
    pub fn new() -> Self {
        BruteForceState {
            discovered_domains: Arc::new(Mutex::new(Vec::new())),
            verification_results: Arc::new(Mutex::new(Vec::new())),
            local_status: Arc::new(RwLock::new(LocalStruct::new())),
            local_stack: Arc::new(RwLock::new(Stack::new())),
            resolver_health: Arc::new(Mutex::new(ResolverHealth::new())),
        }
    }

    /// 添加发现的域名
    pub fn add_discovered_domain(&self, domain: DiscoveredDomain) {
        if let Ok(mut domains) = self.discovered_domains.lock() {
            domains.push(domain);
        }
    }

    /// 获取发现的域名列表
    pub fn get_discovered_domains(&self) -> Vec<DiscoveredDomain> {
        if let Ok(domains) = self.discovered_domains.lock() {
            domains.clone()
        } else {
            Vec::new()
        }
    }

    /// 获取当前已发现域名数量
    pub fn discovered_domain_count(&self) -> usize {
        if let Ok(domains) = self.discovered_domains.lock() {
            domains.len()
        } else {
            0
        }
    }

    /// 清空发现的域名列表
    pub fn clear_discovered_domains(&self) {
        if let Ok(mut domains) = self.discovered_domains.lock() {
            domains.clear();
        }
    }

    /// 添加验证结果
    pub fn add_verification_result(&self, result: VerificationResult) {
        if let Ok(mut results) = self.verification_results.lock() {
            results.push(result);
        }
    }

    /// 获取验证结果列表
    pub fn get_verification_results(&self) -> Vec<VerificationResult> {
        if let Ok(results) = self.verification_results.lock() {
            results.clone()
        } else {
            Vec::new()
        }
    }

    /// 清空验证结果列表
    pub fn clear_verification_results(&self) {
        if let Ok(mut results) = self.verification_results.lock() {
            results.clear();
        }
    }

    /// 检查本地状态是否为空（所有查询是否完成）
    pub fn is_local_status_empty(&self) -> bool {
        match self.local_status.read() {
            Ok(local_status) => local_status.empty(),
            Err(_) => true,
        }
    }

    /// 获取超时数据
    pub fn get_timeout_data(
        &self,
        max_length: usize,
        timeout_seconds: u64,
    ) -> Vec<crate::local_struct::LocalRetryStruct> {
        match self.local_status.write() {
            Ok(mut local_status) => local_status.get_timeout_data(max_length, timeout_seconds),
            Err(_) => Vec::new(),
        }
    }

    /// 从索引搜索并删除
    pub fn search_from_index_and_delete(
        &self,
        index: u32,
    ) -> Result<crate::local_struct::LocalRetryStruct, Box<dyn std::error::Error>> {
        match self.local_status.write() {
            Ok(mut local_status) => local_status
                .search_from_index_and_delete(index)
                .map_err(|e| e),
            Err(e) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to acquire write lock: {}", e),
            ))),
        }
    }

    /// 添加状态表项
    pub fn append_status(&self, value: crate::model::StatusTable, index: u32) {
        if let Ok(mut local_status) = self.local_status.write() {
            local_status.append(value, index);
        }
    }

    /// 推送到本地栈
    pub fn push_to_stack(&self, index: usize) {
        if let Ok(mut stack) = self.local_stack.write() {
            if stack.length <= 50000 {
                stack.push(index);
            }
        }
    }

    /// 从回收栈中弹出一个索引
    pub fn pop_from_stack(&self) -> Option<usize> {
        match self.local_stack.write() {
            Ok(mut stack) => stack.pop(),
            Err(_) => None,
        }
    }

    /// 清空实例内的查询状态
    pub fn clear_query_state(&self) {
        if let Ok(mut local_status) = self.local_status.write() {
            *local_status = LocalStruct::new();
        }

        if let Ok(mut local_stack) = self.local_stack.write() {
            *local_stack = Stack::new();
        }

        if let Ok(mut resolver_health) = self.resolver_health.lock() {
            *resolver_health = ResolverHealth::new();
        }
    }

    pub fn choose_resolver(&self, resolvers: &[String], routing_key: &str) -> Option<String> {
        match self.resolver_health.lock() {
            Ok(mut resolver_health) => resolver_health.choose_resolver(resolvers, routing_key),
            Err(_) => resolvers.first().cloned(),
        }
    }

    pub fn record_resolver_success(&self, resolver: &str, rtt_millis: f64) {
        if let Ok(mut resolver_health) = self.resolver_health.lock() {
            resolver_health.record_success(resolver, rtt_millis);
        }
    }

    pub fn record_resolver_timeout(&self, resolver: &str) {
        if let Ok(mut resolver_health) = self.resolver_health.lock() {
            resolver_health.record_timeout(resolver);
        }
    }

    pub fn record_resolver_failure(&self, resolver: &str) {
        if let Ok(mut resolver_health) = self.resolver_health.lock() {
            resolver_health.record_failure(resolver);
        }
    }

    pub fn current_dns_timeout_seconds(&self, cap_seconds: u64) -> u64 {
        match self.resolver_health.lock() {
            Ok(resolver_health) => resolver_health.timeout_seconds(cap_seconds),
            Err(_) => cap_seconds.max(1),
        }
    }
}

impl Default for BruteForceState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_thread_safety() {
        let state = Arc::new(BruteForceState::new());
        let mut handles = vec![];

        // 启动多个线程同时操作状态
        for i in 0..10 {
            let state_clone = state.clone();
            let handle = thread::spawn(move || {
                let domain = DiscoveredDomain {
                    domain: format!("test{}.example.com", i),
                    value: format!("192.168.1.{}", i),
                    query_type: crate::QueryType::A,
                    record_type: "A".to_string(),
                    timestamp: chrono::Utc::now().timestamp() as u64,
                };
                state_clone.add_discovered_domain(domain);
            });
            handles.push(handle);
        }

        // 等待所有线程完成
        for handle in handles {
            handle.join().unwrap();
        }

        // 验证结果
        let domains = state.get_discovered_domains();
        assert_eq!(domains.len(), 10);
    }

    #[test]
    fn test_state_isolation() {
        let state1 = BruteForceState::new();
        let state2 = BruteForceState::new();

        let domain1 = DiscoveredDomain {
            domain: "test1.example.com".to_string(),
            value: "192.168.1.1".to_string(),
            query_type: crate::QueryType::A,
            record_type: "A".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let domain2 = DiscoveredDomain {
            domain: "test2.example.com".to_string(),
            value: "192.168.1.2".to_string(),
            query_type: crate::QueryType::A,
            record_type: "A".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        state1.add_discovered_domain(domain1);
        state2.add_discovered_domain(domain2);

        assert_eq!(state1.get_discovered_domains().len(), 1);
        assert_eq!(state2.get_discovered_domains().len(), 1);
        assert_ne!(
            state1.get_discovered_domains()[0].domain,
            state2.get_discovered_domains()[0].domain
        );
    }
}
