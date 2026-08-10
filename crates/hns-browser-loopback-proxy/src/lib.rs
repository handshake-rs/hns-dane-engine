//! Authenticated loopback proxy selected through an explicit platform contract.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

#[cfg(all(feature = "chromium", feature = "mobile"))]
compile_error!("select exactly one hns-browser-loopback-proxy platform feature");
#[cfg(not(any(feature = "chromium", feature = "mobile")))]
compile_error!("select one hns-browser-loopback-proxy platform feature");

#[cfg(feature = "chromium")]
include!("chromium/lib.rs");
#[cfg(feature = "mobile")]
include!("mobile/lib.rs");
