pub(crate) trait Sizable {
    fn size(&self) -> usize {
        self.size_in_bytes()
    }

    fn size_in_bytes(&self) -> usize;
}
