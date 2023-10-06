use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use windows_sys::w;
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
        return Err(Error::CertificateOperation(get_last_error("Opening memory store.")));
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
        return Err(Error::CertificateOperation(get_last_error("Opening user store.")));
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
        return Err(Error::ThumbprintEncoding(get_last_error("Encrypting string.")));
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
        return Err(Error::CertificateOperation(get_last_error("Adding certificate to memory store.")));
    }

    if unsafe { CertFreeCertificateContext(cert_context) } == 0 {
        return Err(Error::CertificateOperation(get_last_error("Releasing certificate context.")));
    }

    if unsafe { CertCloseStore(user_store, CERT_CLOSE_STORE_CHECK_FLAG) } == 0 {
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
        memory_store,
        &mut pfx_blob,
        null_mut(),
        null_mut(),
        export_flags
    ) } == 0 {
        return Err(Error::CertificateOperation(get_last_error("Size computation failed.")));
    } else {
        pfx_vec = vec![0; pfx_blob.cbData as usize];
        pfx_blob.pbData = pfx_vec.as_ptr() as _;
        if unsafe { PFXExportCertStoreEx(
            memory_store,
            &mut pfx_blob,
            null_mut(),
            null_mut(),
            export_flags
        ) } == 0 {
            return Err(Error::CertificateOperation(get_last_error("Exporting certficiate.")));   
        }
    }

    if unsafe { CertCloseStore(memory_store, CERT_CLOSE_STORE_CHECK_FLAG) } == 0 {
        return Err(Error::CertificateOperation(get_last_error("Closing memory store")));
    }

    // pfx_vec should contain the DER encoded certificate with private keys and all
    return Ok(pfx_vec);
}


fn get_last_error(default_msg: &str) -> String {
    // The below implementation is for a FFI interface to call
    // GetLastError in C code to avoid issues with the current
    // rust wrapper: https://github.com/microsoft/windows-rs/issues/2639
    // Once the fix gets merged, this code can be removed and replaced with:
    //
    //     let err = unsafe { GetLastError() };
    //     get_last_error_ex();
    //     return windows::Win32::Foundation::WIN32_ERROR(err)
    //         .to_hresult().message().to_string();    

    let mut buffer: Vec<u16> = vec![0;1000];
    let size = unsafe { GetWindowsErrorMessage(buffer.as_mut_ptr()) };
    if size == 0 {
        return String::from(default_msg);
    }

    return trim_u16_str(buffer).unwrap_or(String::from(default_msg));
}

fn trim_u16_str(data: Vec<u16>) -> Option<String> {
    // filters out nulls
    let trimmed: Vec<u16> = data
        .into_iter()
        .filter_map(|x| match x { 0 => None, _ => Some(x) })
        .collect();
    // check and remove newline
    let n = trimmed.len();
    let mut trimmed = &trimmed[0..n];
    if trimmed[n-1] == 10 && trimmed[n-2] == 13 {
        trimmed = &trimmed[0..n-2];
    }
    let msg = String::from_utf16(trimmed);
    match msg {
        Ok(msg) => Some(msg),
        Err(_) => None
    }
}

extern "C" {
    fn GetWindowsErrorMessage(str: *mut u16) -> usize;
}

#[cfg(test)]
mod native_tests {
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
        // This cert fails?!
        let cert_data = load_system_certificate("72f26338e9a4aefa3d54fe2ab66aaf85ce711805").unwrap();
        assert!(cert_data.len() > 0);
    }
}
