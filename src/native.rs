use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use windows_sys::w;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertOpenStore, CryptStringToBinaryW,
    CertAddCertificateContextToStore, CertFreeCertificateContext, PFXExportCertStoreEx,
    CERT_CLOSE_STORE_CHECK_FLAG, CERT_FIND_HASH, CERT_OPEN_STORE_FLAGS,
    CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_INTEGER_BLOB,
    CRYPT_STRING_HEXRAW, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    CERT_STORE_ADD_USE_EXISTING, EXPORT_PRIVATE_KEYS,
    REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY,
};

#[derive(Debug)]
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
        null(),
    ) };

    if memory_store.is_null() {
        return Err(Error::CertificateOperation(String::from("Opening memory store")));
    }

    let store_name = w!("My");
    let user_store = unsafe { CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        CERT_QUERY_ENCODING_TYPE::default(),
        HCRYPTPROV_LEGACY::default(),
        CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
        store_name as *const c_void,
    ) };

    if user_store.is_null() {
        return Err(Error::CertificateOperation(String::from("Opening user store")));
    }

    let cert_thumbprint = OsStr::new(thumbprint)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let cert_thumbprint = cert_thumbprint.as_ptr() as *const u16;

    let hash_vec = vec![0; thumbprint.len() as usize];
    let mut hash_blob = CRYPT_INTEGER_BLOB {
        cbData: thumbprint.len() as u32,
        pbData: hash_vec.as_ptr() as _,
    };


    if unsafe { CryptStringToBinaryW(
        cert_thumbprint,
        hash_blob.cbData,
        CRYPT_STRING_HEXRAW,
        hash_blob.pbData,
        &mut hash_blob.cbData,
        null_mut(),
        null_mut(),
    ) } == 0 {
        return Err(Error::ThumbprintEncoding(get_last_error()));
    }

    let cert_context = unsafe { CertFindCertificateInStore(
        user_store,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &hash_blob as *const CRYPT_INTEGER_BLOB as *const c_void,
        null_mut(),
    ) };

    if cert_context.is_null() {
        return Err(Error::FindCertificate);
    }

    if unsafe { CertAddCertificateContextToStore(
        memory_store,
        cert_context,
        CERT_STORE_ADD_USE_EXISTING,
        null_mut()
    ) } == 0 {
        return Err(Error::CertificateOperation(String::from("Adding certificate to memory store")));
    }

    if unsafe { CertFreeCertificateContext(cert_context) } == 0 {
        return Err(Error::CertificateOperation(String::from("Releasing certificate context")));
    }

    if unsafe { CertCloseStore(user_store, CERT_CLOSE_STORE_CHECK_FLAG) } == 0 {
        return Err(Error::CertificateOperation(String::from("Closing user store")));   
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

    if unsafe { PFXExportCertStoreEx(
        memory_store,
        &mut pfx_blob,
        null_mut(),
        null_mut(),
        EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
    ) } == 0 {
        return Err(Error::CertificateOperation(String::from("Compute PFX size")));   
    } else {
        pfx_vec = vec![0; pfx_blob.cbData as usize];
        pfx_blob.pbData = pfx_vec.as_ptr() as _;
        if unsafe { PFXExportCertStoreEx(
            memory_store,
            &mut pfx_blob,
            null_mut(),
            null_mut(),
            EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
        ) } == 0 {
            return Err(Error::CertificateOperation(String::from("Export PFX")));   
        }
    }

    if unsafe { CertCloseStore(memory_store, CERT_CLOSE_STORE_CHECK_FLAG) } == 0 {
        return Err(Error::CertificateOperation(String::from("Closing memory store")));
    }

    // pfx_vec should contain the DER encoded certificate with private keys and all
    return Ok(pfx_vec);
}


fn get_last_error() -> String {
    // we only use the 'windows' crate for this error mapping thingy,
    // but it has issues with cert/sspi errors, which do not get mapped correctly
    // see: https://github.com/microsoft/windows-rs/issues/2639
    let err = unsafe { GetLastError() };
    return windows::Win32::Foundation::WIN32_ERROR(err)
        .to_hresult().message().to_string();
}
