#[derive(Debug)]
pub struct Stack<T> {
    items: Vec<T>,
    pub length: usize,
}

impl<T> Stack<T> {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            length: 0,
        }
    }

    pub fn push(&mut self, data: T) {
        self.items.push(data);
        self.length = self.items.len();
    }

    pub fn pop(&mut self) -> Option<T> {
        let value = self.items.pop();
        self.length = self.items.len();
        value
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.items.len()
    }
}

impl<T> Default for Stack<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Stack;

    #[test]
    fn stack_preserves_lifo_order() {
        let mut stack = Stack::new();
        stack.push(1usize);
        stack.push(2usize);
        stack.push(3usize);

        assert_eq!(stack.length, 3);
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert_eq!(stack.pop(), None);
        assert_eq!(stack.length, 0);
    }
}
