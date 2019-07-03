use std::{fmt::{Debug, Display}, hash::Hash, str::FromStr};

/// The interface for a generic network.
pub trait Network:
    Copy
    + Clone
    + Debug
    + Display
    + Default
    + Send
    + Sync
    + 'static
    + Eq
    + Hash
{

}
