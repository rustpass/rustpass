/// An AutoType setting associated with an Entry
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoType {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociation>,
}

/// A window association associated with an AutoType setting
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoTypeAssociation {
    pub window: Option<String>,
    pub sequence: Option<String>,
}
