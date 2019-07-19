use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr
};

/// The interface for a generic network.
pub trait Network: Copy + Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

#[derive(Debug, Fail)]
pub enum NetworkError {

    #[fail(display = "invalid network: {}", _0)]
    InvalidNetwork(String),
}
