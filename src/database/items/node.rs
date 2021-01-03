use super::{
    Entry,
    Group,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node<'a> {
    Group(&'a Group),
    Entry(&'a Entry),
}

/// An iterator over Groups and Entries
pub struct NodeIter<'a> {
    queue: Vec<Node<'a>>,
}

impl<'a> NodeIter<'a> {
    pub fn new(queue: Vec<Node<'a>>) -> Self {
        NodeIter { queue }
    }
}

impl<'a> Iterator for NodeIter<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        let res = self.queue.pop();

        if let Some(Node::Group(ref g)) = res {
            self.queue
                .extend(g.entries.iter().map(|(_, e)| Node::Entry(&e)));
            self.queue
                .extend(g.child_groups.iter().map(|(_, g)| Node::Group(&g)));
        }

        res
    }
}
