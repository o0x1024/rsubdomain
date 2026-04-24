use crate::model::StatusTable;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::error::Error;
use std::time::SystemTime;

#[derive(Debug)]
pub struct LocalRetryStruct {
    pub v: StatusTable,
    pub index: u32,
}

#[derive(Debug)]
pub struct LocalStruct {
    items: HashMap<u32, StatusTable>,
    timeout_queue: BinaryHeap<Reverse<(u64, u32)>>,
}

impl LocalStruct {
    // Create a new LocalStruct
    pub fn new() -> Self {
        LocalStruct {
            items: HashMap::new(),
            timeout_queue: BinaryHeap::new(),
        }
    }

    // Return the number of items in the stack
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.items.len()
    }

    #[allow(dead_code)]
    pub fn empty(&self) -> bool {
        self.len() == 0
    }

    pub fn append(&mut self, node: StatusTable, index: u32) {
        self.timeout_queue.push(Reverse((node.timeout_at, index)));
        self.items.insert(index, node);
    }

    // Search and delete node
    #[allow(dead_code)]
    pub fn search_from_index_and_delete(
        &mut self,
        index: u32,
    ) -> Result<LocalRetryStruct, Box<dyn Error>> {
        match self.items.remove(&index) {
            Some(value) => Ok(LocalRetryStruct { v: value, index }),
            None => Err("data not found".into()),
        }
    }

    // Get timeout data, with an optional limit on the number of items returned
    #[allow(dead_code)]
    pub fn get_timeout_data(&mut self, max: usize, timeout_seconds: u64) -> Vec<LocalRetryStruct> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut tables = Vec::new();
        let timeout_millis = timeout_seconds.saturating_mul(1000);

        while tables.len() < max {
            let Some(Reverse((due_at, index))) = self.timeout_queue.peek().copied() else {
                break;
            };

            if due_at > current_time {
                break;
            }

            self.timeout_queue.pop();

            let Some(value) = self.items.get(&index).cloned() else {
                continue;
            };
            if value.timeout_at != due_at {
                continue;
            }

            let is_timed_out = current_time.saturating_sub(value.time) >= timeout_millis;
            if is_timed_out {
                if let Some(value) = self.items.remove(&index) {
                    tables.push(LocalRetryStruct { v: value, index });
                }
            }
        }

        tables
    }
}

#[cfg(test)]
mod tests {
    use super::LocalStruct;
    use crate::{model::StatusTable, QueryType};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn build_status(domain: &str, time: u64) -> StatusTable {
        StatusTable {
            domain: domain.to_string(),
            dns: "8.8.8.8".to_string(),
            query_type: QueryType::A,
            time,
            timeout_at: time + 5_000,
            retry: 0,
            domain_level: 1,
        }
    }

    #[test]
    fn get_timeout_data_scans_full_queue_instead_of_stopping_at_first_fresh_item() {
        let now = now_secs() * 1000;
        let mut local = LocalStruct::new();

        local.append(build_status("fresh.example.com", now), 1);
        local.append(build_status("stale.example.com", now - 10_000), 2);

        let timed_out = local.get_timeout_data(10, 5);

        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].v.domain, "stale.example.com");
        assert!(local.search_from_index_and_delete(1).is_ok());
        assert!(local.search_from_index_and_delete(2).is_err());
    }
}
