//! Browser origin transport selected through an explicit platform contract.

#[cfg(all(feature = "chromium", feature = "mobile"))]
compile_error!("select exactly one hns-browser-transport platform feature");
#[cfg(not(any(feature = "chromium", feature = "mobile")))]
compile_error!("select one hns-browser-transport platform feature");

#[cfg(feature = "chromium")]
mod chromium;
#[cfg(feature = "mobile")]
mod mobile;

#[cfg(feature = "chromium")]
pub use chromium::*;
#[cfg(feature = "mobile")]
pub use mobile::*;
