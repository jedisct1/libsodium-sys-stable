#![cfg_attr(not(any(feature = "wasi-component", feature = "wasmer-wai")), no_std)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)] // we can't control bindgen output to make clippy happy

extern crate libc;

mod sodium_bindings;
pub use sodium_bindings::*;

/// Shared cryptographic implementations used by both WIT and WAI components
#[cfg(any(feature = "wasi-component", feature = "wasmer-wai"))]
pub mod crypto_impl;

#[cfg(all(feature = "wasi-component", target_arch = "wasm32"))]
mod component;

#[cfg(all(feature = "wasmer-wai", target_arch = "wasm32"))]
mod wai_component;
