use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use windows::Win32::Foundation::GetLastError;
use windows::core::{w, PCWSTR};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertOpenStore, CryptStringToBinaryW,
    CertAddCertificateContextToStore, CertFreeCertificateContext, PFXExportCertStoreEx,
    CERT_CLOSE_STORE_CHECK_FLAG, CERT_FIND_HASH, CERT_OPEN_STORE_FLAGS,
    CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_INTEGER_BLOB,
    CRYPT_STRING_HEXRAW, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    CERT_STORE_ADD_USE_EXISTING, EXPORT_PRIVATE_KEYS,
    REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
};

#[derive(Debug, PartialEq)]
pub enum Error {
    ThumbprintLength,
    ThumbprintEncoding(String),
    FindCertificate,
    CertificateOperation(String),
}

pub fn load_system_certificate(thumbprint: &str) -> Result<Vec<u8>, Error> {

    if thumbprint.len() != 40 {
        return Err(Error::ThumbprintLength);
    }

    let memory_store = unsafe { CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        CERT_QUERY_ENCODING_TYPE::default(),
        HCRYPTPROV_LEGACY::default(),
        CERT_OPEN_STORE_FLAGS::default(),
        None,
    ) };

    if memory_store.is_err() {
        return Err(Error::CertificateOperation(get_last_error("Opening memory store.")));
    }

    let store_name = w!("My");
    let cert_flags = CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    let user_store = unsafe { CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        CERT_QUERY_ENCODING_TYPE::default(),
        HCRYPTPROV_LEGACY::default(),
        cert_flags,
        Some(store_name.0 as *const c_void),
    ) };

    if user_store.is_err() {
        return Err(Error::CertificateOperation(get_last_error("Opening user store.")));
    }

    let user_store = user_store.unwrap();

    let cert_thumbprint = OsStr::new(thumbprint)
        .encode_wide()
        .collect::<Vec<u16>>();

    let hash_vec = vec![0; thumbprint.len() as usize];
    let mut hash_blob = CRYPT_INTEGER_BLOB {
        cbData: thumbprint.len() as u32,
        pbData: hash_vec.as_ptr() as _,
    };

    if unsafe { CryptStringToBinaryW(
        &cert_thumbprint,
        CRYPT_STRING_HEXRAW,
        Some(hash_blob.pbData),
        &mut hash_blob.cbData,
        None,
        None,
    ) }.is_err() {
        return Err(Error::ThumbprintEncoding(get_last_error("Encrypting string.")));
    }

    let cert_context = unsafe { CertFindCertificateInStore(
        user_store,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        Some(&hash_blob as *const CRYPT_INTEGER_BLOB as *const c_void),
        None,
    ) };

    if cert_context.is_null() {
        return Err(Error::FindCertificate);
    }

    if unsafe { CertAddCertificateContextToStore(
        memory_store.clone().unwrap(),
        cert_context,
        CERT_STORE_ADD_USE_EXISTING,
        None
    ) }.is_err() {
        return Err(Error::CertificateOperation(get_last_error("Adding certificate to memory store.")));
    }

    let freed_cert_context: bool = unsafe { CertFreeCertificateContext(Some(cert_context)) }.into();
    if !freed_cert_context {
        return Err(Error::CertificateOperation(get_last_error("Releasing certificate context.")));
    }

    if unsafe { CertCloseStore(user_store, CERT_CLOSE_STORE_CHECK_FLAG) }.is_err() {
        return Err(Error::CertificateOperation(get_last_error("Closing user store.")));
    }

    // First call sets the size of the certificate in cbData.
    // After the call, a vector of the given size must be allocated,
    // and then the second call to PFXExportCertStoreEx will write the
    // certificate data to the vector provided.
    // This vector can then by written to a file (PFX/DER encoded)
    let pfx_vec: Vec<u8>;
    let mut pfx_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let export_flags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;

    if unsafe { PFXExportCertStoreEx(
        memory_store.clone().unwrap(),
        &mut pfx_blob,
        PCWSTR::null(),
        null_mut(),
        export_flags
    ) }.is_err() {
        return Err(Error::CertificateOperation(get_last_error("Size computation failed.")));
    } else {
        pfx_vec = vec![0; pfx_blob.cbData as usize];
        pfx_blob.pbData = pfx_vec.as_ptr() as _;
        if unsafe { PFXExportCertStoreEx(
            memory_store.clone().unwrap(),
            &mut pfx_blob,
            PCWSTR::null(),
            null_mut(),
            export_flags
        ) }.is_err() {
            return Err(Error::CertificateOperation(get_last_error("Exporting certficiate.")));   
        }
    }

    if unsafe { CertCloseStore(memory_store.unwrap(), CERT_CLOSE_STORE_CHECK_FLAG) }.is_err() {
        return Err(Error::CertificateOperation(get_last_error("Closing memory store")));
    }

    // pfx_vec should contain the DER encoded certificate with private keys and all
    return Ok(pfx_vec);
}


fn get_last_error(default_msg: &str) -> String {
    match unsafe { GetLastError() } {
        Ok(..) => default_msg.to_string(),
        Err(e) => e.message().to_string_lossy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            // initialization code here
        });
    }

    #[test]
    fn checks_for_thumbprint_length() {
        initialize();
        let cert_data = load_system_certificate("foo");
        assert!(cert_data.is_err());
        assert!(cert_data.unwrap_err() == Error::ThumbprintLength);
    }
}
