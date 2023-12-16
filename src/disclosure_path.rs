use crate::Disclosure;

#[derive(Debug, Clone)]
pub struct DisclosurePath {
    pub path: String,
    pub disclosure: Disclosure,
}

impl DisclosurePath {
    pub fn new(path: &str, disclosure: &Disclosure) -> Self {
        DisclosurePath {
            path: path.to_string(),
            disclosure: disclosure.clone(),
        }
    }
}
