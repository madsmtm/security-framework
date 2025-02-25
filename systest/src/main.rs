#![allow(bad_style)]
#![allow(unused)]
#![allow(clippy::all)]
#![allow(deprecated)]
#![allow(deref_nullptr)]
#![allow(invalid_value)] // mem::uninitialized has to stay

use objc2_core_foundation::{CFOptionFlags, CFString, OSStatus};
use core::ffi::*;

use objc2_security::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
