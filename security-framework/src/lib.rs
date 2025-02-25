#![cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]

//! Wrappers around the OSX Security Framework.
#![warn(missing_docs)]
#![allow(non_upper_case_globals)]
#![allow(clippy::manual_non_exhaustive)] // MSRV
#![allow(clippy::bad_bit_mask)] // bitflags

use objc2_security::errSecSuccess;

use crate::base::{Error, Result, OSStatus};
#[cfg(target_os = "macos")]
use crate::os::macos::access::SecAccess;
#[cfg(target_os = "macos")]
use crate::os::macos::keychain::SecKeychain;

#[cfg(test)]
macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(s) => s,
            Err(e) => panic!("{:?}", e),
        }
    };
}

macro_rules! declare_TCFType {
    (
        $(#[$doc:meta])*
        $ty:ident, $raw:ident
    ) => {
        $(#[$doc])*
        #[repr(transparent)]
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $ty(pub(crate) objc2_core_foundation::CFRetained<objc2_security::$raw>);

        impl $ty {
            #[inline]
            pub fn from_raw(raw: &objc2_security::$raw) -> Self {
                Self(objc2_core_foundation::Type::retain(raw))
            }

            #[inline]
            pub fn as_raw(&self) -> &objc2_security::$raw {
                &self.0
            }

            #[inline]
            pub unsafe fn wrap_under_create_rule(raw: *mut objc2_security::$raw) -> Self {
                Self(objc2_core_foundation::CFRetained::from_raw(core::ptr::NonNull::new(raw).unwrap()))
            }
        }
    };
}

#[cfg(all(not(feature = "OSX_10_13"), any(feature = "alpn", feature = "session-tickets")))]
#[macro_use]
mod dlsym;

pub mod access_control;
#[cfg(target_os = "macos")]
pub mod authorization;
pub mod base;
pub mod certificate;
pub mod cipher_suite;
#[cfg(target_os = "macos")]
pub mod cms;
pub mod identity;
pub mod import_export;
pub mod item;
pub mod key;
pub mod os;
pub mod passwords;
pub mod passwords_options;
pub mod policy;
pub mod random;
pub mod secure_transport;
pub mod trust;
#[cfg(target_os = "macos")]
pub mod trust_settings;

#[cfg(target_os = "macos")]
trait Pkcs12ImportOptionsInternals {
    fn keychain(&mut self, keychain: SecKeychain) -> &mut Self;
    fn access(&mut self, access: SecAccess) -> &mut Self;
}

#[cfg(target_os = "macos")]
trait ItemSearchOptionsInternals {
    fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut Self;
}

#[inline(always)]
fn cvt(err: OSStatus) -> Result<()> {
    match err {
        errSecSuccess => Ok(()),
        err => Err(Error::from_code(err)),
    }
}

#[cfg(test)]
mod test {
    use crate::certificate::SecCertificate;

    pub fn certificate() -> SecCertificate {
        let certificate = include_bytes!("../test/server.der");
        p!(SecCertificate::from_der(certificate))
    }
}
