

use std::sync::{Arc, Mutex};



#[derive(Debug)]
struct Node<T> {
    data: T,
    next: Option<Arc<Mutex<Node<T>>>>,
}

#[derive(Debug)]
struct Stack<T> {
    head: Option<Arc<Mutex<Node<T>>>>,
    length: usize,
}
impl<T: Clone> Stack<T> { // Add the Clone trait bound here
    pub fn new() -> Self {
        Stack {
            head: None,
            length: 0,
        }
    }

    pub fn push(&mut self, data: T) {
        let new_node = Arc::new(Mutex::new(Node {
            data,
            next: None,
        }));

        if let Some(head) = self.head.as_ref() {
            new_node.lock().unwrap().next = Some(Arc::clone(head));
        }

        self.head = Some(Arc::clone(&new_node));
        self.length += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        if let Some(head) = self.head.take() {
            self.length -= 1;
            let data = head.lock().unwrap().data.clone();
            self.head = head.lock().unwrap().next.take();
            Some(data)
        } else {
            None
        }
    }

    fn len(&self) -> usize {
        self.length
    }
}



use lazy_static::lazy_static;

lazy_static! {
    pub static ref LOCAL_STACK: Mutex<Stack<i32>> = Mutex::new(Stack::new());
}