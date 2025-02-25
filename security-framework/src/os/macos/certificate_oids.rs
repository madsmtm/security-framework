//! OIDs associated with certificate properties.
use objc2_core_foundation::{CFRetained, CFString, Type};
use objc2_security::kSecOIDX509V1SignatureAlgorithm;

/// An identifier of a property of a certificate.
#[derive(Copy, Clone)]
pub struct CertificateOid(pub(crate) &'static CFString);

#[allow(missing_docs)]
impl CertificateOid {
    #[inline(always)]
    #[must_use]
    pub fn x509_v1_signature_algorithm() -> Self {
        unsafe { Self(kSecOIDX509V1SignatureAlgorithm) }
    }

    /// Returns the underlying raw pointer corresponding to this OID.
    #[inline(always)]
    #[must_use]
    // FIXME: Don't expose &CFString in Rust APIs
    pub fn as_ptr(&self) -> *const CFString {
        self.0
    }

    /// Returns the string representation of the OID.
    #[inline]
    #[must_use]
    // FIXME: Don't expose CFString in Rust APIs
    pub fn to_str(&self) -> CFRetained<CFString> {
        self.0.retain()
    }
}
