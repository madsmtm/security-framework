//! OSX specific extensions to certificate functionality.

use objc2_core_foundation::{CFArray, CFArrayIter, CFData, CFDictionary, CFError, CFRetained, CFString, CFType, Type};
use objc2_security::*;
use std::ptr::{self, NonNull};

use crate::base::Error;
use crate::certificate::SecCertificate;
use crate::cvt;
use crate::key::SecKey;
use crate::os::macos::certificate_oids::CertificateOid;
use crate::os::macos::digest_transform::{Builder, DigestType};

/// An extension trait adding OSX specific functionality to `SecCertificate`.
pub trait SecCertificateExt {
    /// Returns the common name associated with the certificate.
    fn common_name(&self) -> Result<String, Error>;

    /// Returns the public key associated with the certificate.
    #[cfg_attr(not(feature = "OSX_10_14"), deprecated(note = "Uses deprecated SecCertificateCopyPublicKey. Enable OSX_10_14 feature to avoid it"))]
    fn public_key(&self) -> Result<SecKey, Error>;

    /// Returns the set of properties associated with the certificate.
    ///
    /// The `keys` argument can optionally be used to filter the properties loaded to an explicit
    /// subset.
    fn properties(&self, keys: Option<&[CertificateOid]>) -> Result<CertificateProperties, CFRetained<CFError>>;

    /// Returns the SHA-256 fingerprint of the certificate.
    fn fingerprint(&self) -> Result<[u8; 32], CFRetained<CFError>> { unimplemented!() }
}

impl SecCertificateExt for SecCertificate {
    fn common_name(&self) -> Result<String, Error> {
        unsafe {
            let mut string = ptr::null();
            cvt(SecCertificateCopyCommonName(self.as_raw(), NonNull::from(&mut string)))?;
            Ok(CFRetained::from_raw(NonNull::new(string.cast_mut()).unwrap()).to_string())
        }
    }

    #[cfg(feature = "OSX_10_14")]
    fn public_key(&self) -> Result<SecKey, Error> {
        unsafe {
            let key = SecCertificateCopyKey(self);
            if key.is_null() {
                return Err(Error::from_code(-26275));
            }
            Ok(SecKey::wrap_under_create_rule(key))
        }
    }

    #[cfg(not(feature = "OSX_10_14"))]
    fn public_key(&self) -> Result<SecKey, Error> {
        #[allow(deprecated)]
        unsafe {
            let mut key = ptr::null_mut();
            cvt(SecCertificateCopyPublicKey(self.as_raw(), NonNull::from(&mut key)))?;
            Ok(SecKey(CFRetained::from_raw(NonNull::new(key).unwrap())))
        }
    }

    fn properties(&self, keys: Option<&[CertificateOid]>) -> Result<CertificateProperties, CFRetained<CFError>> {
        unsafe {
            let keys = keys.map(|oids| {
                let oids = oids.iter().map(|oid| oid.to_str()).collect::<Vec<_>>();
                CFArray::from_retained_objects(&oids)
            });

            let mut error = ptr::null_mut();

            let dictionary = SecCertificateCopyValues(
                self.as_raw(), keys.as_deref().map(|arr| arr.as_opaque()), &mut error,
            );

            if error.is_null() {
                let dictionary = CFRetained::cast_unchecked(dictionary.unwrap());
                Ok(CertificateProperties(dictionary))
            } else {
                Err(CFRetained::from_raw(NonNull::new(error).unwrap()))
            }
        }
    }

    /// Returns the SHA-256 fingerprint of the certificate.
    fn fingerprint(&self) -> Result<[u8; 32], CFRetained<CFError>> {
        let data = CFData::from_buffer(&self.to_der());
        let hash = Builder::new()
            .type_(DigestType::sha2())
            .length(256)
            .execute(&data)?;
        Ok(hash.to_vec().try_into().unwrap())
    }
}

/// Properties associated with a certificate.
pub struct CertificateProperties(CFRetained<CFDictionary<CFString, CFDictionary<CFString, CFType>>>);

impl CertificateProperties {
    /// Retrieves a specific property identified by its OID.
    #[must_use]
    pub fn get(&self, oid: CertificateOid) -> Option<CertificateProperty> {
            self.0.get(oid.0).map(|value| {
                CertificateProperty(value)
            })

    }
}

/// A property associated with a certificate.
pub struct CertificateProperty(CFRetained<CFDictionary<CFString, CFType>>);

impl CertificateProperty {
    /// Returns the label of this property.
    #[must_use]
    pub fn label(&self) -> CFRetained<CFString> {
        unsafe {
            self.0.get(kSecPropertyKeyLabel).unwrap().downcast().unwrap()
        }
    }

    /// Returns an enum of the underlying data for this property.
    #[must_use]
    pub fn get(&self) -> PropertyType {
        unsafe {
            let type_ = self.0.get(kSecPropertyKeyType).unwrap().downcast::<CFString>().unwrap();
            let value = self.0.get(kSecPropertyKeyValue).unwrap();

            if &*type_ == kSecPropertyTypeSection {
                let array = value.downcast::<CFArray>().unwrap();
                PropertyType::Section(PropertySection(CFRetained::cast_unchecked(array)))
            } else if &*type_ == kSecPropertyTypeString {
                PropertyType::String(value.downcast().unwrap())
            } else {
                PropertyType::__Unknown
            }
        }
    }
}

/// A "section" property.
///
/// Sections are sequences of other properties.
pub struct PropertySection(CFRetained<CFArray<CFDictionary<CFString, CFType>>>);

impl PropertySection {
    /// Returns an iterator over the properties in this section.
    #[inline(always)]
    #[must_use]
    pub fn iter(&self) -> PropertySectionIter<'_> {
        PropertySectionIter(self.0.iter())
    }
}

impl<'a> IntoIterator for &'a PropertySection {
    type IntoIter = PropertySectionIter<'a>;
    type Item = CertificateProperty;

    #[inline(always)]
    fn into_iter(self) -> PropertySectionIter<'a> {
        self.iter()
    }
}

/// An iterator over the properties in a section.
pub struct PropertySectionIter<'a>(CFArrayIter<'a, CFDictionary<CFString, CFType>>);

impl Iterator for PropertySectionIter<'_> {
    type Item = CertificateProperty;

    #[inline]
    fn next(&mut self) -> Option<CertificateProperty> {
        self.0.next().map(|t| CertificateProperty(t.retain()))
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// An enum of the various types of properties.
pub enum PropertyType {
    /// A section.
    Section(PropertySection),
    /// A string.
    String(CFRetained<CFString>),
    #[doc(hidden)]
    __Unknown,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::certificate;
    use std::collections::HashMap;

    #[test]
    fn common_name() {
        let certificate = certificate();
        assert_eq!("foobar.com", p!(certificate.common_name()));
    }

    #[test]
    #[allow(deprecated)]
    fn public_key() {
        let certificate = certificate();
        p!(certificate.public_key());
    }

    #[test]
    fn fingerprint() {
        let certificate = certificate();
        let fingerprint = p!(certificate.fingerprint());
        assert_eq!("af9dd180a326ae08b37e6398f9262f8b9d4c55674a233a7c84975024f873655d", hex::encode(fingerprint));
    }

    #[test]
    fn signature_algorithm() {
        let certificate = certificate();
        let properties = certificate
            .properties(Some(&[CertificateOid::x509_v1_signature_algorithm()]))
            .unwrap();
        let value = properties
            .get(CertificateOid::x509_v1_signature_algorithm())
            .unwrap();
        let section = match value.get() {
            PropertyType::Section(section) => section,
            _ => panic!(),
        };
        let properties = section
            .iter()
            .map(|p| (p.label().to_string(), p.get()))
            .collect::<HashMap<_, _>>();
        let algorithm = match properties["Algorithm"] {
            PropertyType::String(ref s) => s.to_string(),
            _ => panic!(),
        };
        assert_eq!(algorithm, "1.2.840.113549.1.1.5");
    }
}
