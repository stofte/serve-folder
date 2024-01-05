use std::io::Read;
use std::env::{current_dir, set_current_dir};
use std::net::TcpListener;
use std::path::PathBuf;
use std::fs::File;
use std::sync::Arc;
use clap::Parser;
use native_tls::{Identity, TlsAcceptor};

pub mod native;
pub mod server;
pub mod log;
use native::{load_system_certificate, Error};
use server::run_server;
use log::{LogCategory, log};

#[derive(Parser, Debug)]
#[command(about="Simple CLI server utility for hosting directories over HTTP", author = None, version = None, long_about = None)]
struct Args {
    /// Server port
    #[arg(short('p'), long, default_value_t = 8080)]
    port: u16,

    /// Network interface to bind
    #[arg(short('b'), long, default_value = "0.0.0.0")]
    bind: String,

    /// Filepath for TLS certificate
    #[arg(short('f'), long)]
    certificate_filename: Option<String>,

    /// Optional password for the above TLS certificate
    #[arg(short('w'), long)]
    certificate_password: Option<String>,

    /// Locally installed TLS certificate thumprint to use
    #[arg(short('t'), long)]
    certificate_thumbprint: Option<String>,

    /// Default documents list. Specify option multiple times for each value in order of priority.
    #[arg(short('d'), long, default_values = vec!["index.html"])]
    default_documents: Option<Vec<String>>,

    /// Server base directory. Defaults to the current directory if not set.
    wwwroot: Option<PathBuf>,
}

fn main() {

    let args = Args::parse();

    let is_pfx_file = match &args.certificate_filename {
        Some(path) => match std::fs::metadata(&path) {
            Ok(metadata) => metadata.is_file(),
            Err(_) => false
        },
        None => false
    };

    let mut tls_acceptor: Option<Arc<TlsAcceptor>> = None;
    let mut cert_data = vec![];

    // Check if there's a certificate provided via a file or if we should
    // check the store for a certificate thumbprint instead.
    if is_pfx_file {
        let mut file = File::open(args.certificate_filename.unwrap()).unwrap();
        file.read_to_end(&mut cert_data).unwrap();
    } else if let Some(cert_thumbprint) = &args.certificate_thumbprint {
        match load_system_certificate(cert_thumbprint) {
            Ok(pfx_bin) => cert_data = pfx_bin,
            Err(err) => {
                let msg = match err {
                    Error::ThumbprintLength => { "Thumbprint error: SHA1 thumbprint with 40 characters expected".to_string() },
                    Error::ThumbprintEncoding(msg) => { format!("Thumbprint error: {}", msg) },
                    Error::FindCertificate => { format!("Could not find certificate: {}", cert_thumbprint) },
                    Error::CertificateOperation(msg) => { format!("Certificate operation failed: {}", msg) },
                };
                log(LogCategory::Error, &msg);
                return;
            }
        };
    }

    // if we actually obtained a certificate, we try to init native-tls to receive https calls
    if cert_data.len() > 1 {
        // Certs without passwords are usually empty string.
        let cert_pw = args.certificate_password.unwrap_or(String::from(""));
        match Identity::from_pkcs12(&cert_data, &cert_pw) {
            Ok(identity) => {
                let acceptor = TlsAcceptor::new(identity).unwrap();
                let acceptor = Arc::new(acceptor);
                tls_acceptor = Some(acceptor);
            },
            Err(_) => log(LogCategory::Warning, &"Failed to open certificate using provided password. TLS disabled.")
        };
    }

    // Parse and set current directory
    match &args.wwwroot {
        Some(p) => if !set_current_dir(&p).is_ok() {
            log(LogCategory::Warning, &format!(
                "Failed to set \"{}\" as base directory. Using \"{}\" instead.", 
                p.to_string_lossy(),
                current_dir().unwrap().to_string_lossy()
            ));
        },
        None => ()
    };

    let base_dir = current_dir().expect("Failed to get current dir");
    let bind_addr = [args.bind.clone(), args.port.to_string()].join(":");
    let protocol = match tls_acceptor { Some(_) => "https", None => "http" };

    match TcpListener::bind(&bind_addr) {
        Ok(listener) => {
            let local_addr = listener.local_addr().or(bind_addr.parse()).unwrap();
            log(LogCategory::Info, &format!("Serving \"{}\" @ {}://{}", base_dir.to_string_lossy(), protocol, local_addr));
            run_server(listener, &tls_acceptor);
        },
        Err(err) => {
            log(LogCategory::Error, &format!("Could not bind to {}://{}. {}. Exiting ...", protocol, bind_addr, err));
        }
    }
}
