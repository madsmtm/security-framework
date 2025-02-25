//! Support for password entries in the keychain.  Works on both iOS and macOS.
//!
//! If you want the extended keychain facilities only available on macOS, use the
//! version of these functions in the macOS extensions module.

use std::ptr::NonNull;

use crate::base::Result;
use crate::passwords_options::PasswordOptions;
use crate::{cvt, Error};
use objc2_core_foundation::{CFBoolean, CFData, CFDictionary, CFRetained, CFString, CFType};
use objc2_security::{errSecDuplicateItem, errSecParam};
use objc2_security::{kSecReturnData, kSecValueData};
use objc2_security::{SecAuthenticationType, SecProtocolType};
use objc2_security::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

/// Set a generic password for the given service and account.
/// Creates or updates a keychain entry.
pub fn set_generic_password(service: &str, account: &str, password: &[u8]) -> Result<()> {
    let mut options = PasswordOptions::new_generic_password(service, account);
    set_password_internal(&mut options, password)
}

/// Set a generic password using the given password options.
/// Creates or updates a keychain entry.
pub fn set_generic_password_options(password: &[u8], mut options: PasswordOptions) -> Result<()> {
    set_password_internal(&mut options, password)
}

/// Get the generic password for the given service and account.  If no matching
/// keychain entry exists, fails with error code `errSecItemNotFound`.
pub fn get_generic_password(service: &str, account: &str) -> Result<Vec<u8>> {
    let mut options = PasswordOptions::new_generic_password(service, account);
    #[allow(deprecated)]
    options.query.push((
        unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
        CFBoolean::from(true).into_CFType(),
    ));
    #[allow(deprecated)]
    let params = CFDictionary::from_CFType_pairs(&options.query);
    let mut ret: *mut CFType = std::ptr::null();
    cvt(unsafe { SecItemCopyMatching(params, &mut ret) })?;
    get_password_and_release(ret)
}

/// Delete the generic password keychain entry for the given service and account.
/// If none exists, fails with error code `errSecItemNotFound`.
pub fn delete_generic_password(service: &str, account: &str) -> Result<()> {
    let options = PasswordOptions::new_generic_password(service, account);
    #[allow(deprecated)]
    let params = CFDictionary::from_CFType_pairs(&options.query);
    cvt(unsafe { SecItemDelete(params) })
}

/// Set an internet password for the given endpoint parameters.
/// Creates or updates a keychain entry.
#[allow(clippy::too_many_arguments)]
pub fn set_internet_password(
    server: &str,
    security_domain: Option<&str>,
    account: &str,
    path: &str,
    port: Option<u16>,
    protocol: SecProtocolType,
    authentication_type: SecAuthenticationType,
    password: &[u8],
) -> Result<()> {
    let mut options = PasswordOptions::new_internet_password(
        server,
        security_domain,
        account,
        path,
        port,
        protocol,
        authentication_type,
    );
    set_password_internal(&mut options, password)
}

/// Get the internet password for the given endpoint parameters.  If no matching
/// keychain entry exists, fails with error code `errSecItemNotFound`.
pub fn get_internet_password(
    server: &str,
    security_domain: Option<&str>,
    account: &str,
    path: &str,
    port: Option<u16>,
    protocol: SecProtocolType,
    authentication_type: SecAuthenticationType,
) -> Result<Vec<u8>> {
    let mut options = PasswordOptions::new_internet_password(
        server,
        security_domain,
        account,
        path,
        port,
        protocol,
        authentication_type,
    );
    #[allow(deprecated)]
    options.query.push((
        unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
        CFBoolean::from(true).into_CFType(),
    ));
    #[allow(deprecated)]
    let params = CFDictionary::from_CFType_pairs(&options.query);
    let mut ret: *mut CFType = std::ptr::null();
    cvt(unsafe { SecItemCopyMatching(params, &mut ret) })?;
    get_password_and_release(ret)
}

/// Delete the internet password for the given endpoint parameters.
/// If none exists, fails with error code `errSecItemNotFound`.
pub fn delete_internet_password(
    server: &str,
    security_domain: Option<&str>,
    account: &str,
    path: &str,
    port: Option<u16>,
    protocol: SecProtocolType,
    authentication_type: SecAuthenticationType,
) -> Result<()> {
    let options = PasswordOptions::new_internet_password(
        server,
        security_domain,
        account,
        path,
        port,
        protocol,
        authentication_type,
    );
    #[allow(deprecated)]
    let params = CFDictionary::from_CFType_pairs(&options.query);
    cvt(unsafe { SecItemDelete(params) })
}

// This starts by trying to create the password with the given query params.
// If the creation attempt reveals that one exists, its password is updated.
#[allow(deprecated)]
fn set_password_internal(options: &mut PasswordOptions, password: &[u8]) -> Result<()> {
    let query_len = options.query.len();
    options.query.push((
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        CFData::from_buffer(password).into_CFType(),
    ));

    let params = CFDictionary::from_CFType_pairs(&options.query);
    let mut ret = std::ptr::null();
    let status = unsafe { SecItemAdd(params, &mut ret) };
    if status == errSecDuplicateItem {
        let params = CFDictionary::from_CFType_pairs(&options.query[0..query_len]);
        let update = CFDictionary::from_CFType_pairs(&options.query[query_len..]);
        cvt(unsafe { SecItemUpdate(params, update) })
    } else {
        cvt(status)
    }
}

// Having retrieved a password entry, this copies and returns the password.
//
// # Safety
// The data element passed in is assumed to have been returned from a Copy
// call, so it's released after we are done with it.
fn get_password_and_release(data: *mut CFType) -> Result<Vec<u8>> {
    if let Some(data) = NonNull::new(data) {
        let data = unsafe { CFRetained::from_raw(data) };
        if let Some(data) = data.downcast_ref::<CFData>() {
            return Ok(data.to_vec());
        }
    }
    Err(Error::from_code(errSecParam))
}

#[cfg(test)]
mod test {
    use super::*;
    use objc2_security::errSecItemNotFound;

    #[test]
    fn missing_generic() {
        let name = "a string not likely to already be in the keychain as service or account";
        let result = delete_generic_password(name, name);
        match result {
            Ok(()) => (), // this is ok because the name _might_ be in the keychain
            Err(err) if err.code() == errSecItemNotFound => (),
            Err(err) => panic!("missing_generic: delete failed with status: {}", err.code()),
        };
        let result = get_generic_password(name, name);
        match result {
            Ok(bytes) => panic!("missing_generic: get returned {bytes:?}"),
            Err(err) if err.code() == errSecItemNotFound => (),
            Err(err) => panic!("missing_generic: get failed with status: {}", err.code()),
        };
        let result = delete_generic_password(name, name);
        match result {
            Ok(()) => panic!("missing_generic: second delete found a password"),
            Err(err) if err.code() == errSecItemNotFound => (),
            Err(err) => panic!("missing_generic: delete failed with status: {}", err.code()),
        };
    }

    #[test]
    fn roundtrip_generic() {
        let name = "roundtrip_generic";
        set_generic_password(name, name, name.as_bytes()).expect("set_generic_password");
        let pass = get_generic_password(name, name).expect("get_generic_password");
        assert_eq!(name.as_bytes(), pass);
        delete_generic_password(name, name).expect("delete_generic_password");
    }

    #[test]
    #[cfg(feature = "OSX_10_12")]
    fn update_generic() {
        let name = "update_generic";
        set_generic_password(name, name, name.as_bytes()).expect("set_generic_password");
        let alternate = "update_generic_alternate";
        set_generic_password(name, name, alternate.as_bytes()).expect("set_generic_password");
        let pass = get_generic_password(name, name).expect("get_generic_password");
        assert_eq!(pass, alternate.as_bytes());
        delete_generic_password(name, name).expect("delete_generic_password");
    }

    #[test]
    fn missing_internet() {
        let name = "a string not likely to already be in the keychain as service or account";
        let (server, domain, account, path, port, protocol, auth) = (
            name,
            None,
            name,
            "/",
            Some(8080u16),
            SecProtocolType::HTTP,
            SecAuthenticationType::Any,
        );
        let result = delete_internet_password(server, domain, account, path, port, protocol, auth);
        match result {
            Ok(()) => (), // this is ok because the name _might_ be in the keychain
            Err(err) if err.code() == errSecItemNotFound => (),
            Err(err) => panic!(
                "missing_internet: delete failed with status: {}",
                err.code()
            ),
        };
        let result = get_internet_password(server, domain, account, path, port, protocol, auth);
        match result {
            Ok(bytes) => panic!("missing_internet: get returned {bytes:?}"),
            Err(err) if err.code() == errSecItemNotFound => (),
            Err(err) => panic!("missing_internet: get failed with status: {}", err.code()),
        };
        let result = delete_internet_password(server, domain, account, path, port, protocol, auth);
        match result {
            Ok(()) => panic!("missing_internet: second delete found a password"),
            Err(err) if err.code() == errSecItemNotFound => (),
            Err(err) => panic!(
                "missing_internet: delete failed with status: {}",
                err.code()
            ),
        };
    }

    #[test]
    fn roundtrip_internet() {
        let name = "roundtrip_internet";
        let (server, domain, account, path, port, protocol, auth) = (
            name,
            None,
            name,
            "/",
            Some(8080u16),
            SecProtocolType::HTTP,
            SecAuthenticationType::Any,
        );
        set_internet_password(
            server,
            domain,
            account,
            path,
            port,
            protocol,
            auth,
            name.as_bytes(),
        )
        .expect("set_internet_password");
        let pass = get_internet_password(server, domain, account, path, port, protocol, auth)
            .expect("get_internet_password");
        assert_eq!(name.as_bytes(), pass);
        delete_internet_password(server, domain, account, path, port, protocol, auth)
            .expect("delete_internet_password");
    }

    #[test]
    fn update_internet() {
        let name = "update_internet";
        let (server, domain, account, path, port, protocol, auth) = (
            name,
            None,
            name,
            "/",
            Some(8080u16),
            SecProtocolType::HTTP,
            SecAuthenticationType::Any,
        );

        // cleanup after failed test
        let _ = delete_internet_password(server, domain, account, path, port, protocol, auth);

        set_internet_password(
            server,
            domain,
            account,
            path,
            port,
            protocol,
            auth,
            name.as_bytes(),
        )
        .expect("set_internet_password");
        let alternate = "alternate_internet_password";
        set_internet_password(
            server,
            domain,
            account,
            path,
            port,
            protocol,
            auth,
            alternate.as_bytes(),
        )
        .expect("set_internet_password");
        let pass = get_internet_password(server, domain, account, path, port, protocol, auth)
            .expect("get_internet_password");
        assert_eq!(pass, alternate.as_bytes());
        delete_internet_password(server, domain, account, path, port, protocol, auth)
            .expect("delete_internet_password");
    }
}
