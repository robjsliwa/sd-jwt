use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    ES256,
    ES256K,
    ES384,
    ES512,
    #[default]
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
}
