use super::{
    Node,
    NodeIter,
    Entry,
    Notes,
    Times
};

use std::collections::HashMap;

/// A types group with child groups and entries
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Group {
    pub name: String,
    pub notes: Option<Notes>,
    pub icon_id: u32,
    pub times: Times,
    pub is_expanded: bool,
    pub enable_auto_type: bool,
    pub enable_searching: bool,
    pub last_top_visible_entry: Option<String>,

    pub child_groups: HashMap<String, Group>,

    pub entries: HashMap<String, Entry>,
}

impl Group {
    pub fn new(
        name: &str,
        child_groups: &HashMap<String, Group>,
        entries: &HashMap<String, Entry>
    ) -> Self {
        Self {
            name: name.to_owned(),
            notes: None,
            icon_id: 0,
            times: Times::default(),
            is_expanded: false,
            enable_auto_type: false,
            enable_searching: false,
            last_top_visible_entry: None,
            child_groups: child_groups.clone(),
            entries: entries.clone()
        }
    }

    pub fn root() -> Self {
        Self::new(
            "root",
            &HashMap::new(),
            &HashMap::new()
        )
    }

    pub fn child_group(
        name: &str,
        parent: &mut Group
    ) -> Self {
        let group = Group::new(name, &HashMap::new(), &HashMap::new());
        parent.add_group(name, &group);
        group
    }

    pub fn get(&self, path: &[&str]) -> Option<Node> {
        if path.is_empty() {
            Some(Node::Group(self))
        } else {
            let p = path[0];
            let l = path.len();

            if self.entries.contains_key(p) && l == 1 {
                Some(Node::Entry(&self.entries[p]))
            } else if self.child_groups.contains_key(p) {
                let g = &self.child_groups[p];

                if l == 1 {
                    Some(Node::Group(g))
                } else {
                    let r = &path[1..];
                    g.get(r)
                }
            } else {
                None
            }
        }
    }

    pub fn set_name(&mut self, name: &str) -> &mut Self {
        self.name = name.to_owned();
        self
    }

    pub fn set_notes(&mut self, notes: &Notes) -> &mut Self {
        self.notes = Some(notes.to_owned());
        self
    }

    pub fn set_expanded(&mut self, value: bool) -> &mut Self {
        self.is_expanded = value;
        self
    }

    pub fn set_enable_auto_type(&mut self, value: bool) -> &mut Self {
        self.enable_auto_type = value;
        self
    }

    pub fn set_enable_searching(&mut self, value: bool) -> &mut Self {
        self.enable_searching = value;
        self
    }

    pub fn add_group(&mut self, name: &str, group: &Group) -> &mut Self {
        self.child_groups.insert(name.to_owned(), group.clone());
        self
    }

    pub fn remove_group(&mut self, name: &str) -> &mut Self {
        self.child_groups.remove(name);
        self
    }

    pub fn clear_groups(&mut self) -> &mut Self {
        self.child_groups.clear();
        self
    }

    pub fn has_child_groups(&self) -> bool {
        !self.child_groups.is_empty()
    }

    pub fn add_entry(&mut self, name: &str, entry: &Entry) -> &mut Self {
        self.entries.insert(name.to_owned(), entry.clone());
        self
    }

    pub fn remove_entry(&mut self, name: &str) -> &mut Self {
        self.entries.remove(name);
        self
    }

    pub fn clear_entries(&mut self) -> &mut Self {
        self.entries.clear();
        self
    }

    pub fn has_entries(&self) -> bool {
        !self.entries.is_empty()
    }
}

impl<'a> Group {
    pub fn iter(&'a self) -> NodeIter<'a> {
        (&self).into_iter()
    }
}

impl<'a> IntoIterator for &'a Group {
    type Item = Node<'a>;
    type IntoIter = NodeIter<'a>;

    fn into_iter(self) -> NodeIter<'a> {
        NodeIter::new(vec![Node::Group(&self)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_construct_new() {
        let group = Group::new("test", &HashMap::new(), &HashMap::new());

        assert_that(&group.has_child_groups()).is_false();
        assert_that(&group.has_entries()).is_false();
    }

    #[test]
    fn test_construct_root() {
        let group = Group::root();
        assert_that(&group.has_child_groups()).is_false();
        assert_that(&group.has_entries()).is_false();
    }

    #[test]
    fn test_construct_child_group() {
        let mut parent = Group::root();
        let group = Group::child_group("child", &mut parent);

        assert_that(&parent.has_child_groups()).is_true();
        assert_that(&parent.has_entries()).is_false();
        assert_that(&group.has_child_groups()).is_false();
        assert_that(&group.has_entries()).is_false();
    }

    #[test]
    fn test_construct_modifications() {
        let mut group = Group::new("test", &HashMap::new(), &HashMap::new());

        group
            .set_name("other")
            .set_enable_auto_type(true)
            .set_enable_searching(true)
            .set_expanded(true)
            .set_notes(&Notes {});

        assert_that(&group.name).is_equal_to("other".to_owned());
        assert_that(&group.enable_auto_type).is_true();
        assert_that(&group.enable_searching).is_true();
        assert_that(&group.is_expanded).is_true();
        assert_that(&group.notes).is_some().is_equal_to(Notes{});
    }
}
