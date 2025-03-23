// FnOnce to make sure the cleanup closure is only called once
pub struct Defer<F: FnOnce()> {
    cleanup: Option<F>,
}

impl<F: FnOnce()> Defer<F> {
    pub fn new(cleanup: F) -> Defer<F> {
        Defer {
            cleanup: Some(cleanup),
        }
    }
}

impl<F: FnOnce()> Drop for Defer<F> {
    // drop only takes &mut self, but FnOnce requires ownership
    // -> use an Option, so we can replace it with None
    fn drop(&mut self) {
        if let Some(f) = self.cleanup.take() {
            f();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_defer() {
        // RefCell to allow reading the value even though the defer closure
        // has it mutably borrowed
        let x = std::cell::RefCell::new(0);
        {
            let _defer = Defer::new(|| *x.borrow_mut() += 1);
            assert_eq!(*x.borrow(), 0);
        }

        assert_eq!(*x.borrow(), 1);
    }
}
