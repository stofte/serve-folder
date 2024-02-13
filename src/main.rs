use std::{io::Read, net::SocketAddr};
use std::env::set_current_dir;
use std::path::PathBuf;
use std::fs::File;
use std::sync::Arc;
use std::error::Error;
use clap::Parser;
use native_tls::{Identity, TlsAcceptor};
use socket2::{Socket, TcpKeepalive, Domain, Type};

pub mod native;
pub mod server;
pub mod request;
pub mod log;
pub mod misc;
pub mod stream_reader;
pub mod test_data;
use native::load_system_certificate;
use server::run_server;
use log::{LogCategory, log};

use crate::server::ServerConfiguration;

const DEFAULT_OPTIONS_BIND_VALUE: &str = "0.0.0.0";

#[derive(Parser, Debug)]
#[command(about="Simple CLI server utility for hosting directories over HTTP", author = None, version = None, long_about = None)]
struct Args {
    /// Server port
    #[arg(short('p'), long, default_value_t = 8080)]
    port: u16,

    /// Network interface to bind
    #[arg(short('b'), long, default_value = DEFAULT_OPTIONS_BIND_VALUE)]
    bind: String,

    /// Filepath for TLS certificate
    #[arg(short('f'), long)]
    certificate_filepath: Option<String>,

    /// Optional password for the TLS certificate file
    #[arg(short('w'), long)]
    certificate_password: Option<String>,

    /// Locally installed TLS certificate thumprint to use
    #[arg(short('t'), long)]
    certificate_thumbprint: Option<String>,

    /// Default documents list. Specify option multiple times for each value in order of priority
    #[arg(short('d'), long, default_values = vec!["index.html"])]
    default_documents: Option<Vec<String>>,

    /// Configure/override mime-types for file extensions
    #[arg(short('m'), long, value_parser = parse_key_val::<String, String>)]
    mime_types: Option<Vec<(String, String)>>,

    /// Web root directory. Defaults to the current directory if not set
    wwwroot: Option<PathBuf>,
}

fn main() {

    let args = Args::parse();

    let is_pfx_file = match &args.certificate_filepath {
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
        let mut file = File::open(args.certificate_filepath.unwrap()).unwrap();
        file.read_to_end(&mut cert_data).unwrap();
    } else if let Some(cert_thumbprint) = &args.certificate_thumbprint {
        match load_system_certificate(cert_thumbprint) {
            Ok(pfx_bin) => cert_data = pfx_bin,
            Err(err) => {
                let msg = match err {
                    native::Error::ThumbprintLength => { "Thumbprint error: SHA1 thumbprint with 40 characters expected".to_string() },
                    native::Error::ThumbprintEncoding(msg) => { format!("Thumbprint error: {}", msg) },
                    native::Error::FindCertificate => { format!("Could not find certificate: {}", cert_thumbprint) },
                    native::Error::CertificateOperation(msg) => { format!("Certificate operation failed: {}", msg) },
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
                get_current_dir().to_string_lossy()
            ));
        },
        None => ()
    };

    let addr_str = [args.bind.clone(), args.port.to_string()].join(":");
    let addr = addr_str.parse::<SocketAddr>();

    if addr.is_err() {
        log(LogCategory::Error, &format!("Could not parse bind value {}. Exiting ...", addr_str));
    }
    let addr = addr.expect("Expected ok socket");

    let wwwroot = get_current_dir();
    let protocol = match tls_acceptor { Some(_) => "https", None => "http" };
    let conf = ServerConfiguration::new(wwwroot, args.default_documents, args.mime_types);

    match bind_server_socket(addr) {
        Ok(socket) => {
            print_server_addr(&socket, protocol, &conf.www_root);
            run_server(socket.into(), &tls_acceptor, conf);
        },
        Err(err) => {
            log(LogCategory::Error, &format!("Could not bind to {}://{}. {}. Exiting ...", protocol, addr_str, err));
        }
    }
}

fn bind_server_socket(addr: SocketAddr) -> Result<Socket, std::io::Error> {
    use std::time::Duration;

    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(4));
    socket.set_tcp_keepalive(&keepalive)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.bind(&addr.into())?;
    socket.listen(32)?;
    Ok(socket)
}

fn print_server_addr(sock: &Socket, protocol: &str, base_dir: &PathBuf) {
    let local_addr = sock.local_addr().unwrap().as_socket().unwrap();
    let mut local_str = local_addr.to_string();
    if local_str.starts_with(DEFAULT_OPTIONS_BIND_VALUE) {
        // While we can bind to 0.0.0.0 to match all interfaces, this does not work when connecting,
        // so for clickable links we replace the addr with localhost instead.
        local_str = ["localhost".to_string(), local_addr.port().to_string()].join(":");
    }
    log(LogCategory::Info, &format!("Serving \"{}\" @ {}://{}", base_dir.to_string_lossy(), protocol, local_str));
}

// Used to parse key values in arguments
// See https://docs.rs/clap/latest/clap/_derive/_cookbook/typed_derive/index.html
fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

/// Used to limit usage of current_dir
fn get_current_dir() -> PathBuf {
    use std::env::current_dir;
    current_dir().expect("Failed to read current directory")
}
