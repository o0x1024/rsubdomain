use log::warn;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Node<T> {
    data: T,
    next: Option<Arc<Mutex<Node<T>>>>,
}

#[derive(Debug)]
pub struct Stack<T> {
    head: Option<Arc<Mutex<Node<T>>>>,
    pub length: usize,
}
impl<T: Clone> Stack<T> {
    // Add the Clone trait bound here
    pub fn new() -> Self {
        Stack {
            head: None,
            length: 0,
        }
    }

    pub fn push(&mut self, data: T) {
        let new_node = Arc::new(Mutex::new(Node { data, next: None }));

        if let Some(head) = self.head.as_ref() {
            match new_node.lock() {
                Ok(mut node) => node.next = Some(Arc::clone(head)),
                Err(error) => warn!("Stack lock 被 poison: {}", error),
            }
        }

        self.head = Some(Arc::clone(&new_node));
        self.length += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        if let Some(head) = self.head.take() {
            self.length -= 1;
            let data = match head.lock() {
                Ok(node) => node.data.clone(),
                Err(error) => {
                    warn!("Stack lock 被 poison: {}", error);
                    return None;
                }
            };
            let next = match head.lock() {
                Ok(mut node) => node.next.take(),
                Err(error) => {
                    warn!("Stack lock 被 poison: {}", error);
                    None
                }
            };
            self.head = next;
            Some(data)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.length
    }
}
