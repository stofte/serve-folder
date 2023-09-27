use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use windows_sys::{
    w,
    Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertOpenStore, CryptStringToBinaryW,
        CertAddCertificateContextToStore, CertFreeCertificateContext, PFXExportCertStoreEx,
        CERT_CLOSE_STORE_CHECK_FLAG, CERT_FIND_HASH, CERT_OPEN_STORE_FLAGS,
        CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_INTEGER_BLOB,
        CRYPT_STRING_HEXRAW, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        CERT_STORE_ADD_USE_EXISTING, EXPORT_PRIVATE_KEYS,
        REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY,
    },
};

#[derive(Debug)]
pub enum Error {
    ThumbprintLength,
    ThumbprintEncoding,
    FindCertificateFailed,
    CertificateOperationFailed(String),
}

pub fn load_certificate(thumbprint: &str) -> Result<Vec<u8>, Error> {

    unsafe {
        let memory_store = CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            CERT_QUERY_ENCODING_TYPE::default(),
            HCRYPTPROV_LEGACY::default(),
            CERT_OPEN_STORE_FLAGS::default(),
            null(),
        );

        if memory_store.is_null() {
            return Err(Error::CertificateOperationFailed(String::from("Opening memory store")));
        }

        let store_name = w!("My");
        let user_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE::default(),
            HCRYPTPROV_LEGACY::default(),
            CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
            store_name as *const c_void,
        );

        if user_store.is_null() {
            return Err(Error::CertificateOperationFailed(String::from("Opening user store")));
        }

        let cert_thumbprint = OsStr::new(thumbprint)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<u16>>();
        let cert_thumbprint = cert_thumbprint.as_ptr() as *const u16;

        let hash_vec = vec![0; 40];
        let mut hash_blob = CRYPT_INTEGER_BLOB {
            cbData: 40 as u32,
            pbData: hash_vec.as_ptr() as _,
        };

        if CryptStringToBinaryW(
            cert_thumbprint,
            hash_blob.cbData,
            CRYPT_STRING_HEXRAW,
            hash_blob.pbData,
            &mut hash_blob.cbData,
            null_mut(),
            null_mut(),
        ) == 0 {
            return Err(Error::ThumbprintEncoding);
        }

        let cert_context = CertFindCertificateInStore(
            user_store,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            &hash_blob as *const CRYPT_INTEGER_BLOB as *const c_void,
            null_mut(),
        );

        if cert_context.is_null() {
            return Err(Error::FindCertificateFailed);
        }

        if CertAddCertificateContextToStore(
            memory_store,
            cert_context,
            CERT_STORE_ADD_USE_EXISTING,
            null_mut()
        ) == 0 {
            return Err(Error::CertificateOperationFailed(String::from("Adding certificate to memory store")));
        }

        if CertFreeCertificateContext(cert_context) == 0 {
            return Err(Error::CertificateOperationFailed(String::from("Releasing certificate context")));
        }

        if CertCloseStore(user_store, CERT_CLOSE_STORE_CHECK_FLAG) == 0 {
            return Err(Error::CertificateOperationFailed(String::from("Closing user store")));   
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

        if PFXExportCertStoreEx(
            memory_store,
            &mut pfx_blob,
            null_mut(),
            null_mut(),
            EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
        ) == 0 {
            return Err(Error::CertificateOperationFailed(String::from("Compute PFX size")));   
        } else {
            pfx_vec = vec![0; pfx_blob.cbData as usize];
            pfx_blob.pbData = pfx_vec.as_ptr() as _;
            if PFXExportCertStoreEx(
                memory_store,
                &mut pfx_blob,
                null_mut(),
                null_mut(),
                EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
            ) == 0 {
                return Err(Error::CertificateOperationFailed(String::from("Export PFX")));   
            }
        }

        if CertCloseStore(memory_store, CERT_CLOSE_STORE_CHECK_FLAG) == 0 {
            return Err(Error::CertificateOperationFailed(String::from("Closing memory store")));
        }

        // pfx_vec should contain the DER encoded certificate with private keys and all
        return Ok(pfx_vec);
    }
}
