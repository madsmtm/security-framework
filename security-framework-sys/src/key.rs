use core_foundation_sys::base::CFTypeID;
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::error::CFErrorRef;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use core_foundation_sys::string::CFStringRef;

use crate::base::SecKeyRef;

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub type SecKeyAlgorithm = CFStringRef;

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub type SecKeyOperationType = u32;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub const kSecKeyOperationTypeSign: SecKeyOperationType = 0;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub const kSecKeyOperationTypeVerify: SecKeyOperationType = 1;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub const kSecKeyOperationTypeEncrypt: SecKeyOperationType = 2;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub const kSecKeyOperationTypeDecrypt: SecKeyOperationType = 3;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub const kSecKeyOperationTypeKeyExchange: SecKeyOperationType = 4;

extern "C" {
    pub fn SecKeyGetTypeID() -> CFTypeID;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFErrorRef) -> SecKeyRef;

    #[cfg(any(feature = "OSX_10_13", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCreateWithData(
        keyData: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;

    #[cfg(target_os = "macos")]
    pub fn SecKeyCreateFromData(
        parameters: CFDictionaryRef,
        keyData: CFDataRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCopyExternalRepresentation(key: SecKeyRef, error: *mut CFErrorRef) -> CFDataRef;
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCreateSignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        dataToSign: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyVerifySignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        signedData: CFDataRef,
        signature: CFDataRef,
        error: *mut CFErrorRef,
    ) -> core_foundation_sys::base::Boolean;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCreateEncryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        plaintext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCreateDecryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        ciphertext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyIsAlgorithmSupported(
        key: SecKeyRef,
        operation: SecKeyOperationType,
        algorithm: SecKeyAlgorithm,
    ) -> core_foundation_sys::base::Boolean;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn SecKeyCopyKeyExchangeResult(
        privateKey: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        publicKey: SecKeyRef,
        parameters: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
macro_rules! names {
    ($( $(# $meta:literal )* $x:ident),*) => {
        extern "C" {
            $($(#[cfg(feature = $meta)])* pub static $x: SecKeyAlgorithm;)*
        }
    }
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
names! {
    kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM,
    kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM,
    kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM,
    kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM,
    kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM,

    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM,
    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM,
    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM,
    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM,

    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM,

    #"OSX_10_13" kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM,
    #"OSX_10_13" kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM,
    #"OSX_10_13" kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
    #"OSX_10_13" kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM,
    #"OSX_10_13" kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM,

    kSecKeyAlgorithmECDSASignatureRFC4754,

    kSecKeyAlgorithmECDSASignatureDigestX962,
    kSecKeyAlgorithmECDSASignatureDigestX962SHA1,
    kSecKeyAlgorithmECDSASignatureDigestX962SHA224,
    kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
    kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
    kSecKeyAlgorithmECDSASignatureDigestX962SHA512,

    kSecKeyAlgorithmECDSASignatureMessageX962SHA1,
    kSecKeyAlgorithmECDSASignatureMessageX962SHA224,
    kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
    kSecKeyAlgorithmECDSASignatureMessageX962SHA384,
    kSecKeyAlgorithmECDSASignatureMessageX962SHA512,

    kSecKeyAlgorithmECDHKeyExchangeCofactor,
    kSecKeyAlgorithmECDHKeyExchangeStandard,
    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1,
    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1,
    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224,
    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256,
    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384,
    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512,
    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224,
    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384,
    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512,

    kSecKeyAlgorithmRSAEncryptionRaw,
    kSecKeyAlgorithmRSAEncryptionPKCS1,

    kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA512,

    kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM,
    kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM,

    kSecKeyAlgorithmRSASignatureRaw,

    kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,

    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512,

    kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
    kSecKeyAlgorithmRSASignatureDigestPSSSHA512,

    kSecKeyAlgorithmRSASignatureMessagePSSSHA1,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA224,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA384,
    kSecKeyAlgorithmRSASignatureMessagePSSSHA512
}
