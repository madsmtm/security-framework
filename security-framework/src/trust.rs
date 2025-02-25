//! Trust evaluation support.

use objc2_core_foundation::{CFArray, CFError, CFData, CFDate, CFIndex, CFRetained};
use objc2_security::*;
use std::ptr::{self, NonNull};

use crate::base::Result;
use crate::certificate::SecCertificate;
use crate::cvt;
use crate::key::SecKey;
use crate::policy::SecPolicy;

/// The result of trust evaluation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrustResult(SecTrustResultType);

impl TrustResult {
    /// An invalid setting or result.
    pub const INVALID: Self = Self(SecTrustResultType::Invalid);

    /// You may proceed.
    pub const PROCEED: Self = Self(SecTrustResultType::Proceed);

    /// Indicates a denial by the user, do not proceed.
    pub const DENY: Self = Self(SecTrustResultType::Deny);

    /// The certificate is implicitly trusted.
    pub const UNSPECIFIED: Self = Self(SecTrustResultType::Unspecified);

    /// Indicates a trust policy failure that the user can override.
    pub const RECOVERABLE_TRUST_FAILURE: Self = Self(SecTrustResultType::RecoverableTrustFailure);

    /// Indicates a trust policy failure that the user cannot override.
    pub const FATAL_TRUST_FAILURE: Self = Self(SecTrustResultType::FatalTrustFailure);

    /// An error not related to trust validation.
    pub const OTHER_ERROR: Self = Self(SecTrustResultType::OtherError);
}

impl TrustResult {
    /// Returns true if the result is "successful" - specifically `PROCEED` or `UNSPECIFIED`.
    #[inline]
    #[must_use]
    pub fn success(self) -> bool {
        matches!(self, Self::PROCEED | Self::UNSPECIFIED)
    }
}

declare_TCFType! {
    /// A type representing a trust evaluation for a certificate.
    SecTrust, SecTrust
}

unsafe impl Sync for SecTrust {}
unsafe impl Send for SecTrust {}

#[cfg(target_os = "macos")]
bitflags::bitflags! {
    /// The option flags used to configure the evaluation of a `SecTrust`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TrustOptions: u32 {
        /// Allow expired certificates (except for the root certificate).
        const ALLOW_EXPIRED = SecTrustOptionFlags::AllowExpired.0;
        /// Allow CA certificates as leaf certificates.
        const LEAF_IS_CA = SecTrustOptionFlags::LeafIsCA.0;
        /// Allow network downloads of CA certificates.
        const FETCH_ISSUER_FROM_NET = SecTrustOptionFlags::FetchIssuerFromNet.0;
        /// Allow expired root certificates.
        const ALLOW_EXPIRED_ROOT = SecTrustOptionFlags::AllowExpiredRoot.0;
        /// Require a positive revocation check for each certificate.
        const REQUIRE_REVOCATION_PER_CERT =  SecTrustOptionFlags::RequireRevPerCert.0;
        /// Use TrustSettings instead of anchors.
        const USE_TRUST_SETTINGS = SecTrustOptionFlags::UseTrustSettings.0;
        /// Treat properly self-signed certificates as anchors implicitly.
        const IMPLICIT_ANCHORS = SecTrustOptionFlags::ImplicitAnchors.0;
    }
}

impl SecTrust {
    /// Creates a `SecTrustRef` that is configured with a certificate chain, for validating
    /// that chain against a collection of policies.
    pub fn create_with_certificates(
        certs: &[SecCertificate],
        policies: &[SecPolicy],
    ) -> Result<Self> {
        let certs = certs.iter().map(|cert| cert.0).collect::<Vec<_>>();
        let certs: CFRetained<CFArray<objc2_security::SecCertificate>> = CFArray::from_retained_objects(&certs);
        let policies = policies.iter().map(|policy| policy.0).collect::<Vec<_>>();
        let policies = CFArray::from_retained_objects(&policies);
        let mut trust = ptr::null_mut();
        unsafe {
            cvt(SecTrustCreateWithCertificates(
                &certs,
                Some(&policies),
                NonNull::from(&mut trust),
            ))?;
            Ok(Self::wrap_under_create_rule(trust))
        }
    }

    /// Sets the date and time against which the certificates in this trust object
    /// are verified.
    #[inline]
    pub fn set_trust_verify_date(&mut self, date: &CFDate) -> Result<()> {
        unsafe { cvt(SecTrustSetVerifyDate(&self.0, date)) }
    }

    /// Sets additional anchor certificates used to validate trust.
    pub fn set_anchor_certificates(&mut self, certs: &[SecCertificate]) -> Result<()> {
        let certs = certs.iter().map(|cert| cert.0).collect::<Vec<_>>();
        let certs = CFArray::from_retained_objects(&certs);

        unsafe {
            cvt(SecTrustSetAnchorCertificates(
                &self.0,
                Some(certs.as_opaque()),
            ))
        }
    }

    /// Retrieves the anchor (root) certificates stored by macOS
    #[cfg(target_os = "macos")]
    pub fn copy_anchor_certificates() -> Result<Vec<SecCertificate>> {
        let mut array: *const CFArray = ptr::null();

        unsafe {
            cvt(SecTrustCopyAnchorCertificates(NonNull::from(&mut array)))?;
        }

        if let Some(array) = NonNull::new(array.cast::<CFArray<objc2_security::SecCertificate>>().cast_mut()) {
            let array = unsafe { CFRetained::from_raw(array) };
            Ok(array.into_iter().map(|c| SecCertificate(c)).collect())
        } else {
            Ok(vec![])
        }
    }

    /// If set to `true`, only the certificates specified by
    /// `set_anchor_certificates` will be trusted, but not globally trusted
    /// certificates.
    #[inline]
    pub fn set_trust_anchor_certificates_only(&mut self, only: bool) -> Result<()> {
        unsafe { cvt(SecTrustSetAnchorCertificatesOnly(&self.0, only)) }
    }

    /// Sets the policy used to evaluate trust.
    #[inline]
    pub fn set_policy(&mut self, policy: &SecPolicy) -> Result<()> {
        unsafe { cvt(SecTrustSetPolicies(&self.0, policy.as_raw())) }
    }

    /// Sets option flags for customizing evaluation of a trust object.
    #[cfg(target_os = "macos")]
    #[inline]
    pub fn set_options(&mut self, options: TrustOptions) -> Result<()> {
        unsafe { cvt(SecTrustSetOptions(&self.0, SecTrustOptionFlags(options.bits()))) }
    }

    /// Indicates whether this trust object is permitted to
    /// fetch missing intermediate certificates from the network.
    pub fn get_network_fetch_allowed(&mut self) -> Result<bool> {
        let mut allowed = 0;

        unsafe { cvt(SecTrustGetNetworkFetchAllowed(&self.0, NonNull::from(&mut allowed)))? };

        Ok(allowed != 0)
    }

    /// Specifies whether this trust object is permitted to
    /// fetch missing intermediate certificates from the network.
    #[inline]
    pub fn set_network_fetch_allowed(&mut self, allowed: bool) -> Result<()> {
        unsafe { cvt(SecTrustSetNetworkFetchAllowed(&self.0, allowed)) }
    }

    /// Attaches Online Certificate Status Protocol (OSCP) response data
    /// to this trust object.
    pub fn set_trust_ocsp_response<I: Iterator<Item = impl AsRef<[u8]>>>(
        &mut self,
        ocsp_response: I,
    ) -> Result<()> {
        let response: Vec<CFRetained<CFData>> = ocsp_response
            .into_iter()
            .map(|bytes| CFData::from_buffer(bytes.as_ref()))
            .collect();

        let response = CFArray::from_retained_objects(&response);

        unsafe { cvt(SecTrustSetOCSPResponse(&self.0, Some(&response))) }
    }

    /// Attaches signed certificate timestamp data to this trust object.
    #[cfg(any(feature = "OSX_10_14", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn set_signed_certificate_timestamps<I: Iterator<Item = impl AsRef<[u8]>>>(
        &mut self,
        scts: I,
    ) -> Result<()> {
        let scts: Vec<CFData> = scts
            .into_iter()
            .map(|bytes| &CFData::from_buffer(bytes.as_()))
            .collect();

        let scts = CFArray::from_CFTypes(&scts);

        unsafe { cvt(SecTrustSetSignedCertificateTimestamps(&self.0, scts)) }
    }

    /// Returns the public key for a leaf certificate after it has been evaluated.
    #[inline]
    pub fn copy_public_key(&mut self) -> Result<SecKey> {
        #[allow(deprecated)]
        unsafe { Ok(SecKey(SecTrustCopyPublicKey(&self.0).unwrap())) }
    }

    /// Evaluates trust.
    #[deprecated(note = "use evaluate_with_error")]
    pub fn evaluate(&self) -> Result<TrustResult> {
        #[allow(deprecated)]
        unsafe {
            let mut result = SecTrustResultType::Invalid;
            cvt(SecTrustEvaluate(&self.0, NonNull::from(&mut result)))?;
            Ok(TrustResult(result))
        }
    }

    /// Evaluates trust. Requires macOS 10.14 or iOS, otherwise it just calls `evaluate()`
    pub fn evaluate_with_error(&self) -> Result<(), CFRetained<CFError>> {
        #[cfg(any(feature = "OSX_10_14", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
        unsafe {
            let mut error: &CFError = ::std::ptr::null_mut();
            if !SecTrustEvaluateWithError(&self.0, &mut error) {
                return Err(CFRetained::from_raw(NonNull::new(error).unwrap()));
            }
            Ok(())
        }
        #[cfg(not(any(feature = "OSX_10_14", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
        #[allow(deprecated)]
        {
            use objc2_security::{errSecNotTrusted, errSecTrustSettingDeny};

            let code = match self.evaluate() {
                Ok(res) if res.success() => return Ok(()),
                Ok(TrustResult::DENY) => errSecTrustSettingDeny,
                Ok(_) => errSecNotTrusted,
                Err(err) => err.code(),
            };
            Err(cferror_from_osstatus(code))
        }
    }

    /// Returns the number of certificates in an evaluated certificate chain.
    ///
    /// Note: evaluate must first be called on the `SecTrust`.
    #[inline(always)]
    #[must_use]
    // FIXME: this should have been usize. Don't expose CFIndex in Rust APIs.
    pub fn certificate_count(&self) -> CFIndex {
        unsafe { SecTrustGetCertificateCount(&self.0) }
    }

    /// Returns a specific certificate from the certificate chain used to evaluate trust.
    ///
    /// Note: evaluate must first be called on the `SecTrust`.
    #[deprecated(note = "deprecated by Apple")]
    #[must_use]
    pub fn certificate_at_index(&self, ix: CFIndex) -> Option<SecCertificate> {
        #[allow(deprecated)]
        unsafe {
            if self.certificate_count() <= ix {
                None
            } else {
                SecTrustGetCertificateAtIndex(&self.0, ix).map(SecCertificate)
            }
        }
    }
}

#[cfg(not(any(feature = "OSX_10_14", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
fn cferror_from_osstatus(code: crate::base::OSStatus) -> CFRetained<CFError> {
    use objc2_core_foundation::{kCFErrorDomainOSStatus, CFErrorCreate};

    unsafe {
        CFErrorCreate(None, kCFErrorDomainOSStatus, code as _, None).unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::policy::SecPolicy;
    use crate::secure_transport::SslProtocolSide;
    use crate::test::certificate;
    use crate::trust::SecTrust;

    #[test]
    #[allow(deprecated)]
    fn create_with_certificates() {
        let cert = certificate();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io"));
        let trust = SecTrust::create_with_certificates(&[cert], &[ssl_policy]).unwrap();
        assert!(!trust.evaluate().unwrap().success());
    }

    #[test]
    fn create_with_certificates_new() {
        let cert = certificate();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io"));
        let trust = SecTrust::create_with_certificates(&[cert], &[ssl_policy]).unwrap();
        assert!(trust.evaluate_with_error().is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn certificate_count_and_at_index() {
        let cert = certificate();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io"));
        let trust = SecTrust::create_with_certificates(&[cert], &[ssl_policy]).unwrap();
        trust.evaluate().unwrap();

        let count = trust.certificate_count();
        assert_eq!(count, 1);

        let cert_bytes = trust.certificate_at_index(0).unwrap().to_der();
        assert_eq!(cert_bytes, certificate().to_der());
    }

    #[test]
    #[allow(deprecated)]
    fn certificate_count_and_at_index_new() {
        let cert = certificate();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io"));
        let trust = SecTrust::create_with_certificates(&[cert], &[ssl_policy]).unwrap();
        assert!(trust.evaluate_with_error().is_err());

        let count = trust.certificate_count();
        assert_eq!(count, 1);

        let cert_bytes = trust.certificate_at_index(0).unwrap().to_der();
        assert_eq!(cert_bytes, certificate().to_der());
    }

    #[test]
    #[allow(deprecated)]
    fn certificate_at_index_out_of_bounds() {
        let cert = certificate();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io"));

        let trust = SecTrust::create_with_certificates(&[cert.clone()], &[ssl_policy.clone()]).unwrap();
        trust.evaluate().unwrap();
        assert!(trust.certificate_at_index(1).is_none());

        let trust = SecTrust::create_with_certificates(&[cert], &[ssl_policy]).unwrap();
        assert!(trust.evaluate_with_error().is_err());
        assert!(trust.certificate_at_index(1).is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn set_policy() {
        let cert = certificate();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io.bogus"));
        let mut trust = SecTrust::create_with_certificates(&[cert], &[ssl_policy]).unwrap();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io"));
        trust.set_policy(&ssl_policy).unwrap();
        assert!(!trust.evaluate().unwrap().success());
    }

    #[test]
    fn set_policy_new() {
        let cert = certificate();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io.bogus"));
        let mut trust = SecTrust::create_with_certificates(&[cert], &[ssl_policy]).unwrap();
        let ssl_policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some("certifi.io"));
        trust.set_policy(&ssl_policy).unwrap();
        assert!(trust.evaluate_with_error().is_err());
    }
}
