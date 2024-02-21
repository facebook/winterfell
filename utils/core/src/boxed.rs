#[cfg(not(feature = "std"))]
pub use alloc::boxed::Box;

#[cfg(feature = "std")]
pub use std::boxed::Box;
