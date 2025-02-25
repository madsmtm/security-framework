//! OSX specific functionality for keys.
#![allow(deprecated)]
use objc2_core_foundation::{CFData, CFDictionary, CFError, CFRetained};
use objc2_security::kSecAttrKeyType;
use objc2_security::SecKeyCreateFromData;
use std::ptr;
use std::ptr::NonNull;

use crate::key::{KeyType, SecKey};

/// An extension trait adding OSX specific functionality to `SecKey`.
pub trait SecKeyExt {
    /// Creates a new `SecKey` from a buffer containing key data.
    fn from_data(key_type: KeyType, key_data: &CFData) -> Result<SecKey, CFRetained<CFError>>;
}

impl SecKeyExt for SecKey {
    fn from_data(key_type: KeyType, key_data: &CFData) -> Result<Self, CFRetained<CFError>> {
        unsafe {
            let dict = CFDictionary::from_slices(
                &[kSecAttrKeyType],
                &[key_type.to_str()],
            );

            let mut err = ptr::null_mut();
            let key = SecKeyCreateFromData(
                dict.as_opaque(),
                key_data,
                &mut err,
            );
            if let Some(key) = key {
                Ok(Self(key))
            } else {
                Err(unsafe { CFRetained::from_raw(NonNull::new(err).unwrap()) })
            }
        }
    }
}
