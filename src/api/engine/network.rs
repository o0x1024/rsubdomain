use crate::device;
#[cfg(feature = "dns-resolver")]
use crate::input::parse_bandwidth;
#[cfg(not(feature = "dns-resolver"))]
use crate::input::parse_bandwidth;
use crate::speed_test::BandwidthLimiter;
use crate::EthTable;
use log::{info, warn};

use super::SubdomainBruteEngine;
use crate::api::SubdomainResult;

impl SubdomainBruteEngine {
    pub(super) fn create_bandwidth_limiter(
        bandwidth_limit: Option<&str>,
    ) -> Result<Option<BandwidthLimiter>, Box<dyn std::error::Error>> {
        match bandwidth_limit {
            Some(limit) => Ok(Some(BandwidthLimiter::new(parse_bandwidth(limit)?))),
            None => Ok(None),
        }
    }

    pub(super) async fn select_network_device(
        &self,
    ) -> Result<EthTable, Box<dyn std::error::Error>> {
        if let Some(device_name) = &self.config.device {
            match device::get_device_by_name_for_dns(
                device_name,
                &self.config.resolvers,
                self.config.transport,
            ) {
                Ok(device) => {
                    if !self.config.silent {
                        info!("使用指定网络设备: {}", device_name);
                    }
                    Ok(device)
                }
                Err(error) => {
                    if !self.config.silent {
                        warn!(
                            "指定网络设备 {} 不可用于当前传输模式 {:?}: {}，尝试自动检测",
                            device_name, self.config.transport, error
                        );
                    }
                    device::auto_get_devices_for_dns(
                        &self.config.resolvers,
                        self.config.transport,
                    )
                        .await
                        .map_err(|detect_error| {
                            format!(
                                "自动检测网络设备失败: {}; 指定设备错误: {}",
                                detect_error, error
                            )
                            .into()
                        })
                }
            }
        } else {
            device::auto_get_devices_for_dns(&self.config.resolvers, self.config.transport)
                .await
                .map_err(Into::into)
        }
    }

    pub(super) fn build_bandwidth_limiter(&self) -> Option<BandwidthLimiter> {
        self._bandwidth_limiter.clone()
    }

    pub(super) fn collect_discovered_results(&self) -> Vec<SubdomainResult> {
        self.state
            .get_discovered_domains()
            .into_iter()
            .map(|domain| SubdomainResult {
                domain: domain.domain,
                value: domain.value,
                query_type: domain.query_type,
                record_type: domain.record_type,
                timestamp: domain.timestamp,
                #[cfg(feature = "verify")]
                verified: None,
                #[cfg(feature = "dns-resolver")]
                dns_records: None,
            })
            .collect()
    }
}
