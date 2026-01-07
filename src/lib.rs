#![cfg_attr(not(feature = "wasi-component"), no_std)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)] // we can't control bindgen output to make clippy happy

extern crate libc;


mod sodium_bindings;
pub use sodium_bindings::*;

#[cfg(all(feature = "wasi-component", target_arch = "wasm32"))]
mod component;
