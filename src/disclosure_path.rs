use crate::Disclosure;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
