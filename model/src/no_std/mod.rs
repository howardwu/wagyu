#[cfg(not(feature = "std"))]
#[doc(hidden)]
pub mod io;

#[cfg(not(feature = "std"))]
#[doc(hidden)]
pub use alloc::{format, string::String, string::ToString, vec, vec::Vec};

#[cfg(feature = "std")]
#[doc(hidden)]
pub use std::{format, string::String, string::ToString, vec, vec::Vec};
