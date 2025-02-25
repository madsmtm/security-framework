//! Keychain item support.

use std::fmt;

declare_TCFType! {
    /// A type representing a keychain item.
    SecKeychainItem, SecKeychainItem
}

unsafe impl Sync for SecKeychainItem {}
unsafe impl Send for SecKeychainItem {}

impl fmt::Debug for SecKeychainItem {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SecKeychainItem").finish_non_exhaustive()
    }
}
