//! Access functionality.

declare_TCFType! {
    /// A type representing access settings.
    SecAccess, SecAccess
}

unsafe impl Sync for SecAccess {}
unsafe impl Send for SecAccess {}
