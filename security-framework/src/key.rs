//! Encryption key support


use crate::cvt;
use objc2_core_foundation::{CFString, CFRetained, CFMutableDictionary};
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use objc2_core_foundation::{CFBoolean, CFData, CFDictionary, CFNumber, CFError};

use objc2_security::{
    kSecAttrKeyTypeRSA, kSecValueRef,
    SecItemDelete, SecKeyAlgorithm,
};
#[cfg(target_os = "macos")]
use objc2_security::{
    kSecAttrKeyType3DES, kSecAttrKeyTypeDSA, kSecAttrKeyTypeAES,
    kSecAttrKeyTypeDES, kSecAttrKeyTypeRC4, kSecAttrKeyTypeCAST,
};

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use objc2_security::{
    kSecAttrApplicationLabel,
    kSecAttrIsPermanent, kSecAttrLabel, kSecAttrKeyType,
    kSecAttrKeySizeInBits, kSecPrivateKeyAttrs, kSecAttrAccessControl,
    SecKeyAlgorithm,
    SecKeyCopyAttributes, SecKeyCopyExternalRepresentation,
    SecKeyCreateSignature, SecKeyCreateRandomKey,
    SecKeyCopyPublicKey,
    SecKeyCreateDecryptedData, SecKeyCreateEncryptedData,
};
use std::fmt;
use core::ptr::NonNull;


use crate::base::Error;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use crate::item::Location;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use crate::access_control::SecAccessControl;

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
macro_rules! names {
    ($( $(# $meta:literal )* $i:ident => $x:ident),*) => {
        #[non_exhaustive]
        #[derive(Copy, Clone)]
        #[allow(missing_docs)]
        pub enum Algorithm {
            $( $(#[cfg(feature = $meta)])* $i, )*
        }

        impl From<Algorithm> for SecKeyAlgorithm {
            fn from(m: Algorithm) -> Self {
                unsafe { match m {
                    $( $(#[cfg(feature = $meta)])* Algorithm::$i => objc2_security::$x, )*
                } }
            }
        }
    }
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
names! {
    ECIESEncryptionStandardX963SHA1AESGCM => kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM,
    ECIESEncryptionStandardX963SHA224AESGCM => kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM,
    ECIESEncryptionStandardX963SHA256AESGCM => kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM,
    ECIESEncryptionStandardX963SHA384AESGCM => kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM,
    ECIESEncryptionStandardX963SHA512AESGCM => kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM,

    ECIESEncryptionStandardVariableIVX963SHA224AESGCM => kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM,
    ECIESEncryptionStandardVariableIVX963SHA256AESGCM => kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM,
    ECIESEncryptionStandardVariableIVX963SHA384AESGCM => kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM,
    ECIESEncryptionStandardVariableIVX963SHA512AESGCM => kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM,

    ECIESEncryptionCofactorVariableIVX963SHA224AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM,
    ECIESEncryptionCofactorVariableIVX963SHA256AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
    ECIESEncryptionCofactorVariableIVX963SHA384AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM,
    ECIESEncryptionCofactorVariableIVX963SHA512AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM,

    #"OSX_10_13" ECIESEncryptionCofactorX963SHA1AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM,
    #"OSX_10_13" ECIESEncryptionCofactorX963SHA224AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM,
    #"OSX_10_13" ECIESEncryptionCofactorX963SHA256AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
    #"OSX_10_13" ECIESEncryptionCofactorX963SHA384AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM,
    #"OSX_10_13" ECIESEncryptionCofactorX963SHA512AESGCM => kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM,

    ECDSASignatureRFC4754 => kSecKeyAlgorithmECDSASignatureRFC4754,

    ECDSASignatureDigestX962 => kSecKeyAlgorithmECDSASignatureDigestX962,
    ECDSASignatureDigestX962SHA1 => kSecKeyAlgorithmECDSASignatureDigestX962SHA1,
    ECDSASignatureDigestX962SHA224 => kSecKeyAlgorithmECDSASignatureDigestX962SHA224,
    ECDSASignatureDigestX962SHA256 => kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
    ECDSASignatureDigestX962SHA384 => kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
    ECDSASignatureDigestX962SHA512 => kSecKeyAlgorithmECDSASignatureDigestX962SHA512,

    ECDSASignatureMessageX962SHA1 => kSecKeyAlgorithmECDSASignatureMessageX962SHA1,
    ECDSASignatureMessageX962SHA224 => kSecKeyAlgorithmECDSASignatureMessageX962SHA224,
    ECDSASignatureMessageX962SHA256 => kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
    ECDSASignatureMessageX962SHA384 => kSecKeyAlgorithmECDSASignatureMessageX962SHA384,
    ECDSASignatureMessageX962SHA512 => kSecKeyAlgorithmECDSASignatureMessageX962SHA512,

    ECDHKeyExchangeCofactor => kSecKeyAlgorithmECDHKeyExchangeCofactor,
    ECDHKeyExchangeStandard => kSecKeyAlgorithmECDHKeyExchangeStandard,
    ECDHKeyExchangeCofactorX963SHA1 => kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1,
    ECDHKeyExchangeStandardX963SHA1 => kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1,
    ECDHKeyExchangeCofactorX963SHA224 => kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224,
    ECDHKeyExchangeCofactorX963SHA256 => kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256,
    ECDHKeyExchangeCofactorX963SHA384 => kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384,
    ECDHKeyExchangeCofactorX963SHA512 => kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512,
    ECDHKeyExchangeStandardX963SHA224 => kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224,
    ECDHKeyExchangeStandardX963SHA256 => kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
    ECDHKeyExchangeStandardX963SHA384 => kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384,
    ECDHKeyExchangeStandardX963SHA512 => kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512,

    RSAEncryptionRaw => kSecKeyAlgorithmRSAEncryptionRaw,
    RSAEncryptionPKCS1 => kSecKeyAlgorithmRSAEncryptionPKCS1,

    RSAEncryptionOAEPSHA1 => kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
    RSAEncryptionOAEPSHA224 => kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
    RSAEncryptionOAEPSHA256 => kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
    RSAEncryptionOAEPSHA384 => kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
    RSAEncryptionOAEPSHA512 => kSecKeyAlgorithmRSAEncryptionOAEPSHA512,

    RSAEncryptionOAEPSHA1AESGCM => kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM,
    RSAEncryptionOAEPSHA224AESGCM => kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM,
    RSAEncryptionOAEPSHA256AESGCM => kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM,
    RSAEncryptionOAEPSHA384AESGCM => kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM,
    RSAEncryptionOAEPSHA512AESGCM => kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM,

    RSASignatureRaw => kSecKeyAlgorithmRSASignatureRaw,

    RSASignatureDigestPKCS1v15Raw => kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
    RSASignatureDigestPKCS1v15SHA1 => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
    RSASignatureDigestPKCS1v15SHA224 => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224,
    RSASignatureDigestPKCS1v15SHA256 => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
    RSASignatureDigestPKCS1v15SHA384 => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
    RSASignatureDigestPKCS1v15SHA512 => kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,

    RSASignatureMessagePKCS1v15SHA1 => kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
    RSASignatureMessagePKCS1v15SHA224 => kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224,
    RSASignatureMessagePKCS1v15SHA256 => kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
    RSASignatureMessagePKCS1v15SHA384 => kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
    RSASignatureMessagePKCS1v15SHA512 => kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,

    RSASignatureDigestPSSSHA1 => kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
    RSASignatureDigestPSSSHA224 => kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
    RSASignatureDigestPSSSHA256 => kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
    RSASignatureDigestPSSSHA384 => kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
    RSASignatureDigestPSSSHA512 => kSecKeyAlgorithmRSASignatureDigestPSSSHA512,

    RSASignatureMessagePSSSHA1 => kSecKeyAlgorithmRSASignatureMessagePSSSHA1,
    RSASignatureMessagePSSSHA224 => kSecKeyAlgorithmRSASignatureMessagePSSSHA224,
    RSASignatureMessagePSSSHA256 => kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
    RSASignatureMessagePSSSHA384 => kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
    RSASignatureMessagePSSSHA512 => kSecKeyAlgorithmRSASignatureMessagePSSSHA512
}

/// Types of `SecKey`s.
#[derive(Debug, Copy, Clone)]
pub struct KeyType(&'static CFString);

#[allow(missing_docs)]
impl KeyType {
    #[inline(always)]
    #[must_use]
    pub fn rsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeRSA) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn dsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeDSA) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn aes() -> Self {
        unsafe { Self(kSecAttrKeyTypeAES) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn des() -> Self {
        unsafe { Self(kSecAttrKeyTypeDES) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn triple_des() -> Self {
        unsafe { Self(kSecAttrKeyType3DES) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn rc4() -> Self {
        unsafe { Self(kSecAttrKeyTypeRC4) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn cast() -> Self {
        unsafe { Self(kSecAttrKeyTypeCAST) }
    }

    #[inline(always)]
    #[must_use]
    pub fn ec() -> Self {
        use objc2_security::kSecAttrKeyTypeEC;

        unsafe { Self(kSecAttrKeyTypeEC) }
    }

    #[inline(always)]
    #[must_use]
    pub fn ec_sec_prime_random() -> Self {
        use objc2_security::kSecAttrKeyTypeECSECPrimeRandom;

        unsafe { Self(kSecAttrKeyTypeECSECPrimeRandom) }
    }

    pub(crate) fn to_str(&self) -> &CFString {
        &self.0
    }
}

declare_TCFType! {
    /// A type representing an encryption key.
    SecKey, SecKey
}

unsafe impl Sync for SecKey {}
unsafe impl Send for SecKey {}

impl SecKey {
    /// Translates to `SecKeyCreateRandomKey`
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    #[allow(deprecated)]
    #[doc(alias = "SecKeyCreateRandomKey")]
    pub fn new(options: &GenerateKeyOptions) -> Result<Self, CFRetained<CFError>> {
        Self::generate(&options.to_dictionary())
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCreateRandomKey`
    /// `GenerateKeyOptions` provides a helper to create an attribute `CFDictionary`.
    #[deprecated(note = "Use SecKey::new")]
    pub fn generate(attributes: &CFDictionary) -> Result<Self, CFRetained<CFError>> {
        use std::ptr::NonNull;

        let mut error = ::std::ptr::null_mut();
        let sec_key = unsafe { SecKeyCreateRandomKey(attributes, &mut error) };
        if let Some(error) = NonNull::new(error) {
            Err(unsafe { CFRetained::from_raw(error) })
        } else {
            Ok(unsafe { Self(sec_key.unwrap()) })
        }
    }

    /// Returns the programmatic identifier for the key. For keys of class
    /// kSecAttrKeyClassPublic and kSecAttrKeyClassPrivate, the value is the
    /// hash of the public key.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    #[must_use]
    pub fn application_label(&self) -> Option<Vec<u8>> {
        self.attributes()
            .find(unsafe { kSecAttrApplicationLabel.to_void() })
            .map(|v| unsafe { CFData::wrap_under_get_rule(v.cast()) }.to_vec())
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCopyAttributes`
    // TODO: deprecate and remove. CFDictionary should not be exposed in public Rust APIs.
    #[must_use]
    pub fn attributes(&self) -> CFRetained<CFDictionary> {
        let pka = unsafe { SecKeyCopyAttributes(self.to_void() as _) };
        unsafe { CFDictionary::wrap_under_create_rule(pka) }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCopyExternalRepresentation`
    // TODO: deprecate and remove. CFData should not be exposed in public Rust APIs.
    #[must_use]
    pub fn external_representation(&self) -> Option<CFData> {
        let mut error: &CFError = ::std::ptr::null_mut();
        let data = unsafe { SecKeyCopyExternalRepresentation(self.to_void() as _, &mut error) };
        if data.is_null() {
            return None;
        }
        Some(unsafe { CFData::wrap_under_create_rule(data) })
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCopyPublicKey`
    #[must_use]
    pub fn public_key(&self) -> Option<Self> {
        let pub_seckey = unsafe { SecKeyCopyPublicKey(self.0.cast()) };
        if pub_seckey.is_null() {
            return None;
        }

        Some(unsafe { Self::wrap_under_create_rule(pub_seckey) })
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Encrypts a block of data using a public key and specified algorithm
    pub fn encrypt_data(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, CFRetained<CFError>> {
        let mut error = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateEncryptedData(self, algorithm.into(), &CFData::from_buffer(input).as_concrete_Type(), &mut error)
        };

        if error.is_null() {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        } else {
            Err(unsafe { CFRetained::from_raw(NonNull::new(error).unwrap()) })
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Decrypts a block of data using a private key and specified algorithm
    pub fn decrypt_data(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, CFRetained<CFError>> {
        let mut error: &CFError = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateDecryptedData(self, algorithm.into(), &CFData::from_buffer(input).as_concrete_Type(), &mut error)
        };

        if error.is_null() {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        } else {
            Err(unsafe { CFRetained::from_raw(NonNull::new(error).unwrap()) })
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Creates the cryptographic signature for a block of data using a private
    /// key and specified algorithm.
    pub fn create_signature(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, CFRetained<CFError>> {
        let mut error = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateSignature(
                self,
                algorithm.into(),
                &CFData::from_buffer(input).as_concrete_Type(),
                &mut error,
            )
        };

        if error.is_null() {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        } else {
            Err(unsafe { CFRetained::from_raw(NonNull::new(error).unwrap()) })
        }
    }

    /// Verifies the cryptographic signature for a block of data using a public
    /// key and specified algorithm.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn verify_signature(&self, algorithm: Algorithm, signed_data: &[u8], signature: &[u8]) -> Result<bool, CFRetained<CFError>> {
        use std::ptr::NonNull;

        use objc2_security::SecKeyVerifySignature;
        let mut error = std::ptr::null_mut();

        let valid = unsafe {
            SecKeyVerifySignature(
                self,
                algorithm.into(),
                &CFData::from_buffer(signed_data).as_concrete_Type(),
                &CFData::from_buffer(signature).as_concrete_Type(),
                &mut error,
            )
        };

        if let Some(error) = NonNull::new(error) {
            return Err(unsafe { CFRetained::from_raw(error) });
        }
        Ok(valid)
    }

    /// Performs the Diffie-Hellman style of key exchange.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn key_exchange(
        &self,
        algorithm: Algorithm,
        public_key: &Self,
        requested_size: usize,
        shared_info: Option<&[u8]>,
    ) -> Result<Vec<u8>, CFRetained<CFError>> {
        use objc2_core_foundation::CFData;
        use objc2_security::{
            kSecKeyKeyExchangeParameterRequestedSize, kSecKeyKeyExchangeParameterSharedInfo,
        };

        unsafe {
            let mut params = vec![(
                CFString::wrap_under_get_rule(kSecKeyKeyExchangeParameterRequestedSize),
                CFNumber::from(requested_size as i64).into_CFType(),
            )];

            if let Some(shared_info) = shared_info {
                params.push((
                    CFString::wrap_under_get_rule(kSecKeyKeyExchangeParameterSharedInfo),
                    CFData::from_buffer(shared_info).as_CFType(),
                ));
            };

            let parameters = CFDictionary::from_CFType_pairs(&params);

            let mut error: &CFError = std::ptr::null_mut();

            let output = objc2_security::SecKeyCopyKeyExchangeResult(
                self,
                algorithm.into(),
                public_key,
                parameters,
                &mut error,
            );

            if error.is_null() {
                let output = CFData::wrap_under_create_rule(output);
                Ok(output.to_vec())
            } else {
                Err(unsafe { CFRetained::from_raw(NonNull::new(error).unwrap()) })
            }
        }
    }

    /// Translates to `SecItemDelete`, passing in the `SecKeyRef`
    pub fn delete(&self) -> Result<(), Error> {
        let query = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecValueRef }.to_void(),
            self.to_void(),
        )]);

        cvt(unsafe { SecItemDelete(query) })
    }
}

/// Where to generate the key.
#[derive(Debug)]
pub enum Token {
    /// Generate the key in software, compatible with all `KeyType`s.
    Software,
    /// Generate the key in the Secure Enclave such that the private key is not
    /// extractable. Only compatible with `KeyType::ec()`.
    SecureEnclave,
}

/// Helper for creating `CFDictionary` attributes for `SecKey::generate`
/// Recommended reading:
/// <https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains>
#[derive(Debug, Default)]
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub struct GenerateKeyOptions {
    /// kSecAttrKeyType
    #[deprecated(note = "use set_key_type()")]
    pub key_type: Option<KeyType>,
    /// kSecAttrKeySizeInBits
    #[deprecated(note = "use set_size_in_bits()")]
    pub size_in_bits: Option<u32>,
    /// kSecAttrLabel
    #[deprecated(note = "use set_label()")]
    pub label: Option<String>,
    /// kSecAttrTokenID
    #[deprecated(note = "use set_token()")]
    pub token: Option<Token>,
    /// Which keychain to store the key in, if any.
    #[deprecated(note = "use set_location()")]
    pub location: Option<Location>,
    /// Access control
    #[deprecated(note = "use set_access_control()")]
    pub access_control: Option<SecAccessControl>,
    /// `kSecAttrSynchronizable`
    #[cfg(feature = "sync-keychain")]
    synchronizable: Option<bool>,
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
#[allow(deprecated)]
impl GenerateKeyOptions {
    /// Set `key_type`
    pub fn set_key_type(&mut self, key_type: KeyType) -> &mut Self {
        self.key_type = Some(key_type);
        self
    }

    /// Set `size_in_bits`
    pub fn set_size_in_bits(&mut self, size_in_bits: u32) -> &mut Self {
        self.size_in_bits = Some(size_in_bits);
        self
    }

    /// Set `label`
    pub fn set_label(&mut self, label: impl Into<String>) -> &mut Self {
        self.label = Some(label.into());
        self
    }

    /// Set `token`
    pub fn set_token(&mut self, token: Token) -> &mut Self {
        self.token = Some(token);
        self
    }

    /// Set `location`
    pub fn set_location(&mut self, location: Location) -> &mut Self {
        self.location = Some(location);
        self
    }

    /// Set `access_control`
    pub fn set_access_control(&mut self, access_control: SecAccessControl) -> &mut Self {
        self.access_control = Some(access_control);
        self
    }

    /// Set `synchronizable` (`kSecAttrSynchronizable`)
    #[cfg(feature = "sync-keychain")]
    pub fn set_synchronizable(&mut self, synchronizable: bool) -> &mut Self {
        self.synchronizable = Some(synchronizable);
        self
    }

    /// Collect options into a `CFDictioanry`
    // CFDictionary should not be exposed in public Rust APIs.
    #[deprecated(note = "Pass the options to SecKey::new")]
    pub fn to_dictionary(&self) -> CFRetained<CFDictionary> {
        #[cfg(target_os = "macos")]
        use objc2_security::kSecUseKeychain;
        use objc2_security::{
            kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecPublicKeyAttrs,
        };

        let is_permanent = CFBoolean::from(self.location.is_some());
        let mut private_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent }.to_void(),
            is_permanent.to_void(),
        )]);
        if let Some(access_control) = &self.access_control {
            private_attributes.set(unsafe { kSecAttrAccessControl }.to_void(), access_control.to_void());
        }

        let public_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent }.to_void(),
            is_permanent.to_void(),
        )]);

        let key_type = self.key_type.unwrap_or_else(KeyType::rsa).to_str();

        let size_in_bits = self.size_in_bits.unwrap_or(match () {
            #[cfg(target_os = "macos")]
            _ if key_type == KeyType::aes().to_str() => 256,
            _ if key_type == KeyType::rsa().to_str() => 2048,
            _ if key_type == KeyType::ec().to_str() => 256,
            _ if key_type == KeyType::ec_sec_prime_random().to_str() => 256,
            _ => 256,
        });
        let size_in_bits = CFNumber::from(size_in_bits as i32);

        let mut attribute_key_values = vec![
            (unsafe { kSecAttrKeyType }.to_void(), key_type.to_void()),
            (unsafe { kSecAttrKeySizeInBits }.to_void(), size_in_bits.to_void()),
        ];
        #[cfg(target_os = "macos")]
        if key_type != KeyType::aes().to_str() {
                attribute_key_values.push((unsafe { kSecPublicKeyAttrs }.to_void(), public_attributes.to_void()));
                attribute_key_values.push((unsafe { kSecPrivateKeyAttrs }.to_void(), private_attributes.to_void()));
        }

        let label = self.label.as_deref().map(CFString::new);
        if let Some(label) = &label {
            attribute_key_values.push((unsafe { kSecAttrLabel }.to_void(), label.to_void()));
        }

        #[cfg(target_os = "macos")]
        match &self.location {
            #[cfg(feature = "OSX_10_15")]
            Some(Location::DataProtectionKeychain) => {
                use objc2_security::kSecUseDataProtectionKeychain;
                attribute_key_values.push((
                    unsafe { kSecUseDataProtectionKeychain }.to_void(),
                    CFBoolean::true_value().to_void(),
                ));
            }
            Some(Location::FileKeychain(keychain)) => {
                attribute_key_values.push((
                    unsafe { kSecUseKeychain }.to_void(),
                    keychain.to_void(),
                ));
            }
            _ => {}
        }

        match self.token.as_ref().unwrap_or(&Token::Software) {
            Token::Software => {},
            Token::SecureEnclave => {
                attribute_key_values.push((
                    unsafe { kSecAttrTokenID }.to_void(),
                    unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
                ));
            }
        }

        #[cfg(feature = "sync-keychain")]
        if let Some(ref synchronizable) = self.synchronizable {
            attribute_key_values.push((
                 unsafe { objc2_security::kSecAttrSynchronizable }.to_void(),
                CFBoolean::from(*synchronizable).to_void(),
            ));
        }

        CFMutableDictionary::from_CFType_pairs(&attribute_key_values).to_immutable()
    }
}

impl fmt::Debug for SecKey {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SecKey").finish_non_exhaustive()
    }
}
