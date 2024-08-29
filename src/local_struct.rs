use crate::model::StatusTable;
use std::error::Error;
use std::sync::RwLock;
use std::time::SystemTime;

#[derive(Clone)]
#[derive(Debug)]
struct LocalNode {
    v: StatusTable,
    index: u32,
}

#[derive(Debug)]
pub struct LocalRetryStruct {
    pub v: StatusTable,
    pub index: u32,
}

#[derive(Debug)]
pub struct LocalStruct {
    items: Vec<LocalNode>,
}

impl LocalStruct {
    // Create a new LocalStruct
    pub fn new() -> Self {
        LocalStruct {
            items: Vec::new(),
            
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
        let new_node = LocalNode { v: node, index };
        self.items.push(new_node);
    }

    // Search and delete node
    #[allow(dead_code)]
    pub fn search_from_index_and_delete(
        &mut self,
        index: u32,
    ) -> Result<LocalRetryStruct, Box<dyn Error>> {
        for i in 0..self.items.len() {
            if self.items[i].index == index {
                let ret = LocalRetryStruct {
                    v: self.items[i].v.clone(),
                    index,
                };
                self.items.remove(i);
                return Ok(ret);
            }
        }
        Err("data not found".into())
    }

    // Get timeout data, with an optional limit on the number of items returned
    #[allow(dead_code)]
    pub fn get_timeout_data(&mut self, max: usize) -> Vec<LocalRetryStruct> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut tables = Vec::new();
        let mut index = 0;

        for i in 0..self.items.len() {
            if current_time - self.items[i].v.time < 5 {
                break;
            }
            if index >= max {
                break;
            }
            index += 1;
            tables.push(LocalRetryStruct {
                v: self.items[i].v.clone(),
                index: self.items[i].index,
            });
        }

        // Remove the processed items
        self.items.drain(0..index);
        tables
    }
}
