use std::sync:: RwLock;
use std::time::SystemTime;
use std::error::Error;
use crate::model:: StatusTable;

#[derive(Clone)]
struct LocalNode {
    v: StatusTable,
    index: u32,
}

struct LocalRetryStruct {
    v: StatusTable,
    index: u32,
}

pub struct LocalStruct {
    items: Vec<LocalNode>,
    lock: RwLock<()>,
}

impl LocalStruct {
    // Create a new LocalStruct
    fn new() -> Self {
        LocalStruct {
            items: Vec::new(),
            lock: RwLock::new(()),
        }
    }

    // Return the number of items in the stack
    #[allow(dead_code)]
    fn len(&self) -> usize {
        let _guard = self.lock.read().unwrap();
        self.items.len()
    }

    #[allow(dead_code)]
    pub fn empty(&self) -> bool {
        self.len() == 0
    }

    pub fn append(&mut self, node: StatusTable, index: u32) {
        let _guard = self.lock.write().unwrap();
        let new_node = LocalNode { v: node, index };
        self.items.push(new_node);
    }

    // Search and delete node
    #[allow(dead_code)]
    fn search_from_index_and_delete(&mut self, index: u32) -> Result<LocalRetryStruct, Box<dyn Error>> {
        let _guard = self.lock.write().unwrap();

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
    fn get_timeout_data(&mut self, max: usize) -> Vec<LocalRetryStruct> {
        let _guard = self.lock.write().unwrap();
        let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
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


use lazy_static::lazy_static;

lazy_static! {
    pub static ref LOCAL_STATUS: RwLock<LocalStruct> = RwLock::new(LocalStruct::new());
}