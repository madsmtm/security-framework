//! Transform support
#![allow(deprecated)]

use objc2_core_foundation::{CFError, CFRetained, CFString, CFType};
use objc2_security::*;
use std::ptr::{self, NonNull};

declare_TCFType! {
    /// A type representing a transform.
    SecTransform, SecTransform
}

unsafe impl Sync for SecTransform {}
unsafe impl Send for SecTransform {}

impl SecTransform {
    /// Sets an attribute of the transform.
    pub fn set_attribute(&mut self, key: &CFString, value: &CFType) -> Result<(), CFRetained<CFError>> {
        unsafe {
            let mut error = ptr::null_mut();
            SecTransformSetAttribute(
                self.as_raw(),
                key,
                value,
                &mut error,
            );
            if let Some(error) = NonNull::new(error) {
                return Err(CFRetained::from_raw(error));
            }

            Ok(())
        }
    }

    /// Executes the transform.
    ///
    /// The return type depends on the type of transform.
    // FIXME: deprecate and remove: don't expose CFType in Rust APIs.
    pub fn execute(&mut self) -> Result<CFRetained<CFType>, CFRetained<CFError>> {
        unsafe {
            let mut error = ptr::null_mut();
            let result = SecTransformExecute(self.as_raw(), &mut error);
            if result.is_null() {
                return Err(unsafe { CFRetained::from_raw(NonNull::new(error).unwrap()) });
            }

            Ok(result)
        }
    }
}
