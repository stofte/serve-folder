use std::io::{BufReader, Read, Write};
use std::fs::{self, File};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use native_tls::{TlsAcceptor, HandshakeError};
use phf::phf_map;
use socket2::{Domain, Socket, TcpKeepalive, Type};
use thiserror::Error;
use crate::log::{LogCategory, log};
use crate::misc::{HttpError, StreamError};
use crate::request::HttpRequest;
use crate::stream::Stream;

#[derive(Clone)]
pub struct ServerConfiguration {
    www_root: PathBuf,
    default_documents: Option<Vec<String>>,
    mime_types: Option<Vec<(String, String)>>,
    /// The max size of the underlying Stream buffer when reciving.
    /// This limits the incoming request in various ways:
    /// 1. The length of any single line in the header
    /// 2. The size of any message body
    buffer_size: usize,
    directory_browsing: bool,
    connection_timeout_ms: u64,
}

pub struct Server {
    conf: ServerConfiguration,
    address: SocketAddr,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    socket: Option<Socket>,
}

impl ServerConfiguration {
    pub fn new(www_root: PathBuf, default_documents: Option<Vec<String>>, mime_types: Option<Vec<(String, String)>>, buffer_size: Option<usize>, directory_browsing: bool, connection_timeout_ms: Option<u64>) -> ServerConfiguration {
        ServerConfiguration {
            www_root,
            default_documents,
            mime_types,
            buffer_size: buffer_size.unwrap_or(10000),
            directory_browsing,
            connection_timeout_ms: connection_timeout_ms.unwrap_or(2000)
        }
    }
}

#[derive(Error, Debug)]
enum Error {
    #[error("Path is directory")]
    PathIsDirectory,
    #[error("Failed to parse path (io)")]
    IOFailed(#[from] std::io::Error),
    #[error("Failed to parse path (glob)")]
    GlobFailed(#[from] glob::PatternError),
    #[error("Failed to parse path")]
    PathParsingFailed,
    #[error("Path must be a file")]
    PathMustBeFile,
    #[error("Failed to read path")]
    PathMetadataFailed(std::io::ErrorKind),
    #[error("The path matches, but requires a redirection")]
    PathRequiresRedirect(String)
}

#[derive(Debug)]
struct RequestedFileInfo {
    file_path: PathBuf,
    file_size: u64,
    mime_type: String
}

static MIMETYPES: phf::Map<&'static str, &'static str> = phf_map! {
    "html" => "text/html",
    "css" => "text/css",
    "js" => "application/javascript",
    "svg" => "image/svg+xml",
    "woff2" => "font/woff2",
    "ico" => "image/x-icon",
    "png" => "image/png",
    "gif" => "image/gif",
    "xml" => "application/xml"
};

/// Handles writing a file response to the tcp stream.
fn handle_response(stream: &mut Stream, request_info: &RequestedFileInfo) -> String {
    let path = &request_info.file_path;
    let f_wrapped = File::open(&path);
    if f_wrapped.is_ok() {
        // File could be opened
        let f = f_wrapped.expect("File result failed");
        let mut br = BufReader::new(f);
        let lines = [
            "HTTP/1.1 200 OK",
            "Cache-Control: no-store",
            &format!("Content-Type: {}", &request_info.mime_type),
            &format!("Content-Length: {}\r\n\r\n", &request_info.file_size),
        ].join("\r\n");

        // We dump the file directly into the response.
        // Ideally we would ensure crlf as newlines, etc.
        if stream.write_all(lines.as_bytes()).is_ok() {
            // All headers written, try to write file
            if stream.write_reader(&mut br).is_ok() {
                format!("{} ({} bytes)", path.to_string_lossy(), request_info.file_size)
            } else {
                let status = format!("Failed to write contents to response");
                log(LogCategory::Warning, &status, file!(), line!());
                status
            }
        } else {
            let status = format!("Failed to write headers to response");
            log(LogCategory::Warning, &status, file!(), line!());
            status
        }
    } else {
        let status = format!("500 Internal Server Error");
        handle_simple_http_response(stream, 500, "Internal Server Error", None);
        log(LogCategory::Info, &status, file!(), line!());
        status
    }
}

/// Helper for writing out HTTP error messages, redirects and other similar
fn handle_simple_http_response(stream: &mut Stream, code: u32, body: &str, headers: Option<Vec<String>>) {
    let status = match code {
        307 => "Temporary Redirect",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
          _ => "Internal Server Error"
    };

    let header = format!("HTTP/1.1 {} {}", code, status);
    let content_type = "Content-Type: text/plain".to_owned();
    let content_length = format!("Content-Length: {}", body.len());

    let mut other_headers = headers.unwrap_or_else(|| Vec::new() as Vec<String>);

    let mut lines = [header].to_vec();
    lines.append(&mut other_headers);
    lines.append(&mut [content_type, content_length, "".to_owned(), body.to_owned()].to_vec());

    stream.write_all(lines.join("\r\n").as_bytes()).unwrap_or_else(|err| {
        // todo impl default formatter?
        log(LogCategory::Warning, &format!("Failed writing error response: {:?}", err), file!(), line!())
    });
}

/// Maps a Http request target to a file path on disk.
/// The file may or may not exist, as other logic runs afterwards.
fn translate_target_to_filepath(target: &Option<String>, conf: &ServerConfiguration) -> Result<PathBuf, Error> {
    use std::path::MAIN_SEPARATOR_STR;
    use normpath::PathExt;

    let target_path = target.as_ref().unwrap();
    let parse_url = String::from("http://localhost") + &target_path;
    let cur_dir = &conf.www_root;
    let fs_path = match url::Url::parse(&parse_url) {
        Ok(url) => {
            let mut url_path = url.path().replace("/", MAIN_SEPARATOR_STR);
            // rust's fs code gets confused if we join a "\", as this
            // will just change the directory to root, eg "C:\"
            url_path = url_path[1..].to_owned();
            let path_buf = Path::new(&cur_dir)
                .join(url_path)
                .normalize_virtually(); // This does not hit the fs, which is what we want
            match path_buf {
                Ok(v) => Ok(v),
                Err(..) => Err(Error::PathParsingFailed)
            }
        },
        Err(_) => Err(Error::PathParsingFailed)
    }?;

    Ok(fs_path.into_path_buf())
}

/// Once a Http request target has been mapped to a file system path like object,
/// this function runs and tries to determine what actual file is matched, if any.
/// 1. File is matched, return
/// 2. Directory is matched:
///    a. If default document is found, return
///    b. Else if directory listing is enabled return (an err indicating this case)
/// 3. Nothing is matched, find number of matches using globbing (some/where.*)
///    a. If a single file is found, return
/// 4. If nothing was matched, fail mapping
fn process_request(file_path: &PathBuf, conf: &ServerConfiguration, request: &HttpRequest) -> Result<RequestedFileInfo, Error> {
    use glob::glob;
    
    let mut file_size = 0;
    let mut file_path = file_path.to_owned();

    match std::fs::metadata(&file_path) {
        Ok(metadata) => {
            if metadata.is_file() {
                // All is good, direct file hit
                file_size = metadata.len();
                Ok(())
            } else if metadata.is_dir() {
                // Check if we have a default doc to return instead
                let m = match map_to_default_document(&file_path, &conf.default_documents, &conf.www_root) {
                    Some(p) => {
                        file_size = p.metadata()?.len();
                        file_path = p;
                        Ok(())
                    },
                    None => {
                        if conf.directory_browsing {
                            Err(Error::PathIsDirectory)
                        } else {
                            log(LogCategory::Info, "Path is directory", file!(), line!());
                            Err(Error::PathMustBeFile)
                        }
                    }
                };
                // if we either have a match against directory browsing or a default doc, 
                // we want to ensure the path ends with a "/", so relative requests function
                // correctly, as serving up "http://localhost/foo" is obviously different from 
                // "http://localhost/foo/" when eg embedded resources are fetched.
                if let Ok(..) = m {
                    // either dir or default docs must have matched, in either case, 
                    // lets redirect to proper folder path ending with a slash.
                    if request.target_ends_with_slash() {
                        m
                    } else {
                        Err(Error::PathRequiresRedirect(format!("{}/", request.target.as_ref().unwrap())))
                    }
                } else {
                    m
                }
            } else {
                log(LogCategory::Info, "Path not handled", file!(), line!());
                Err(Error::PathMustBeFile)
            }
        },
        Err(err) => {
            // Nothing was found, see if a glob can find the file regardle
            let mut matches = glob(&format!("{}.*", file_path.to_string_lossy()))?;
            
            let glob_match_ok = match matches.next() {
                Some(file) => {
                    match file {
                        Ok(p) => {
                            match std::fs::metadata(p.clone()) {
                                Ok(metadata) => {
                                    if metadata.is_file() {
                                        file_size = metadata.len();
                                        file_path = p;
                                        true
                                    } else {
                                        false
                                    }
                                },
                                Err(..) => false
                            }
                        },
                        Err(..) => false
                    }
                },
                None => false
            };

            let prefix_len = conf.www_root.to_string_lossy().len();
            let rel_file_path = file_path.to_string_lossy();
            let rel_file_path = &rel_file_path[prefix_len + 1..];

            // We only want one match
            let single_match = glob_match_ok && matches.next().is_none();
            if single_match {
                // One matched file
                Ok(())
            } else if glob_match_ok {
                // We must have had multiple matches
                log(LogCategory::Info, &format!("Multiple files matched \"{}\"", rel_file_path), file!(), line!());
                Err(Error::PathMustBeFile)
            } else {
                Err(Error::PathMetadataFailed(err.kind()))
            }
        }
    }?;

    Ok(RequestedFileInfo {
        mime_type: get_mimetype(&file_path, &conf.mime_types).to_string(),
        file_size: file_size,
        file_path: file_path,
    })
}

fn write_http_chunk(stream: &mut Stream, chunk: &str) -> Result<(), StreamError> {
    let str = format!("{:x}\r\n{}\r\n", chunk.len(), chunk);
    stream.write_all(str.as_bytes())?;
    Ok(())
}

/// If a Http request matches a folder, this function will write a listing 
/// to the stream, using chunked transfer encoding.
fn process_directory_listing(path: &PathBuf, www_root: &PathBuf, stream: &mut Stream) -> Result<(), StreamError> {
    // do some fiddling about with strings, to find out what the url path prefix should be
    let path_str = path.to_string_lossy().into_owned();
    let www_root_str = www_root.to_string_lossy().into_owned();
    assert!(path_str.starts_with(&www_root_str));
    let mut sub_path = path_str[www_root_str.len()..].replace(std::path::MAIN_SEPARATOR_STR, "/");
    if sub_path.len() == 0 {
        sub_path = "/".to_owned();
    }
    if !sub_path.ends_with("/") {
        sub_path.push_str("/");
    }
    println!("{:?} => {:?}", path.to_str(), sub_path);
    let dir = fs::read_dir(path).expect("path was not a directory");
    let head = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html",
        "Transfer-Encoding: chunked",
        "",
        ""
    ].join("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    write_http_chunk(stream, "<ul>\r\n")?;
    for path in dir {
        let file_name_os = path.unwrap().file_name();
        let s = file_name_os.to_str().unwrap();
        let str = format!("<li><a href=\"{sub_path}{s}\">{s}</a></li>\r\n");
        write_http_chunk(stream, &str)?;
    }
    write_http_chunk(stream, "</ul>\r\n")?;
    write_http_chunk(stream, "")?; // end encoding with empty chunk
    Ok(())
}

fn map_to_default_document(path: &Path, default_documents: &Option<Vec<String>>, www_root: &PathBuf) -> Option<PathBuf> {
    if let Some(doclist) = default_documents {
        let base = www_root.join(&path);
        if let Some(exists) = doclist.iter().find(|f| base.join(f).is_file()) {
            return Some(path.to_owned().join(exists));
        }
    }
    None
}

fn get_mimetype(path: &PathBuf, mimetypes: &Option<Vec<(String, String)>>) -> String {
    let mt = match path.extension() {
        Some(val) => {
            let ext = val.to_string_lossy().to_lowercase();

            let mut mt = "";

            if let Some(mts) = mimetypes {
                if let Some(mt_map) = mts.into_iter().find(|x| x.0 == ext) {
                    mt = &mt_map.1;
                }
            }

            if mt.is_empty() {
                match MIMETYPES.get(&ext) {
                    Some(mime) => mime,
                    None => {
                        log(LogCategory::Warning, &format!("No mimetype for '{}'", ext), file!(), line!());
                        "text/plain"
                    }
                }
            } else {
                mt
            }
        }
        None => "text/plain"
    };
    mt.to_owned()
}

pub fn bind_server_socket(addr: SocketAddr, timeout_ms: u64) -> Result<Socket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(4));
    socket.set_tcp_keepalive(&keepalive)?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    socket.bind(&addr.into())?;
    socket.listen(32)?;
    Ok(socket)
}

fn handle_connection(stream: impl Read + Write, conf: ServerConfiguration) {
    let mut stream = Stream::new(stream, conf.buffer_size);
    loop {
        match stream.next_request() {
            Ok(request) => {
                // todo handle the server response
                match translate_target_to_filepath(&request.target, &conf) {
                    Ok(file_path) => {
                        match process_request(&file_path, &conf, &request) {
                            Ok(file_info) => {
                                handle_response(&mut stream, &file_info);
                            },
                            Err(err) => {
                                match err {
                                    Error::PathRequiresRedirect(path) => {
                                        let location = format!("Location: {}", path).to_owned();
                                        handle_simple_http_response(&mut stream, 307, "", Some(vec![location]));
                                    },
                                    Error::PathIsDirectory => {
                                        // path is directory is only if directory_browsing is enabled
                                        assert!(conf.directory_browsing);
                                        if let Err(_e) = process_directory_listing(&file_path, &conf.www_root, &mut stream) {
                                            // todo if we had an error while printing the listings, we probably also want to break
                                        }
                                    },
                                    _ => {
                                        log(LogCategory::Info, &format!("Error: {:?}", err), file!(), line!());
                                        handle_simple_http_response(&mut stream, 404, "Not Found", None);
                                    }
                                }
                            }
                        };
                    },
                    Err(err) => {
                        // todo: this possibly needs to be bad request?
                        // and we probably want to break the loop, closing the connection
                        handle_simple_http_response(&mut stream, 404, "Not Found", None);
                    }
                }
                // we should only keep the connection alive, if the client indicates this
                if !request.connection_keep_alive() {
                    break;
                }
            },
            Err(err) => {
                match err {
                    HttpError::StreamError(StreamError::BufferOverflow) => {
                        handle_simple_http_response(&mut stream, 400, "", None);
                    },
                    HttpError::MethodNotSupported(..) => {
                        handle_simple_http_response(&mut stream, 405, "", Some(["Allow: GET".to_owned()].to_vec()));
                    },
                    HttpError::StreamError(StreamError::ConnectionTimeout) |
                    HttpError::StreamError(StreamError::ConnectionClosed) | 
                    HttpError::StreamError(StreamError::ConnectionReset) => {
                        // logging is noisy
                    }
                    _ => {
                        println!("handle_connection:Err:{:?}", err);
                        handle_simple_http_response(&mut stream, 500, "", None);
                    }
                };
                // close connection by returning from function, causing
                // the thread to exit and the connection to be dropped
                break;
            }
        }
    }
}

/// Wires the stream up for TLS if this was specified for the server, and
/// then starts a new thread for handling request/responses.
fn setup_connection(stream: TcpStream, tls_acceptor: &Option<Arc<TlsAcceptor>>, conf: ServerConfiguration) {
    match &tls_acceptor {
        Some(acceptor) => {
            match acceptor.accept(stream) {
                Ok(stream) => {
                    thread::spawn(move || handle_connection(stream, conf));
                },
                Err(e) => {
                    match &e {
                        HandshakeError::Failure(ee) => {
                            // Likely because of self-signed not being in trusted roots
                            log(LogCategory::Error, &format!("{}", ee), file!(), line!());
                        },
                        _ => ()
                    }
                }
            }
        },
        None => {
            thread::spawn(move || handle_connection(stream, conf));
        }
    }
}

impl Server {
    pub fn new(conf: ServerConfiguration, address: SocketAddr, tls_acceptor: Option<Arc<TlsAcceptor>>) -> Server {
        Server {
            conf,
            address,
            tls_acceptor,
            socket: None,
        }
    }
    
    pub fn protocol(&self) -> String {
        match self.tls_acceptor { Some(_) => "https".to_owned(), None => "http".to_owned() }
    }

    pub fn bind(&mut self) -> Result<SocketAddr, std::io::Error> {
        let socket = bind_server_socket(self.address, self.conf.connection_timeout_ms)?;
        let local_addr = socket
            .local_addr().expect("socket was not bound")
            .as_socket().expect("socket address was unexpected type");
        self.socket = Some(socket);
        Ok(local_addr)
    }

    pub fn run(&mut self) {
        match self.socket.take() {
            Some(s) => {
                let listener: TcpListener = s.into();
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            setup_connection(stream, &self.tls_acceptor, self.conf.clone());
                        },
                        Err(..) => {
                            // todo log err
                        }
                    };
                }
            },
            None => {
                // todo log err
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::ErrorKind};
    use test_case::test_case;
    use crate::test_data::{
        HTTP_REQ_GET_CARGO_MULTIPLE_MATCH_GLOB_TEST, HTTP_REQ_GET_NON_EXISTENT_FILE, HTTP_REQ_GET_README_GLOB_TEST, HTTP_REQ_GET_README_MD, HTTP_REQ_GET_SRC_DIRECTORY_FOR_LISTING, HTTP_REQ_POST
    };

    fn start_server(conf: Option<ServerConfiguration>) -> SocketAddr {
        let current_dir = std::env::current_dir().unwrap();
        let conf = match conf {
            Some(c) => c,
            None => ServerConfiguration::new(current_dir, None, None, None, false, None)
        };
        let address = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let mut server = Server::new(conf, address, None);
        let addr = server.bind().unwrap();
        thread::spawn(move || server.run());
        addr
    }

    fn call_server_and_read_response(address: SocketAddr, request: &str) -> String {
        let request = request.to_owned();
        let client_handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write(request.as_bytes()).unwrap();
            let mut buf = [0;10000];
            let read_c = stream.read(&mut buf).unwrap();
            String::from_utf8_lossy(&buf[0..read_c]).into_owned()
        });
        client_handle.join().unwrap()
    }

    // These tests generally assume that the tests are run with project root as the current_dir.
 
    // // todo: code now rejects paths without initial slashes
    // #[test_case("../../../foo"; "Regular")]
    // #[test_case("..\\..\\..\\foo"; "Regular 2nd")]
    // #[test_case("%2e%2e%2ffoo"; "Encoded")]
    // #[test_case("..%c0%affoo"; "Encoded 2nd")]
    // fn handles_path_traversel_attempts(str: &str) {
    //     let conf = ServerConfiguration::new(PathBuf::new(), None, None);
    //     let request_header = format!("GET {} HTTP/1.1", str);
    //     match process_request(&request_header, &conf) {
    //         Ok(..) => panic!("Request path should not parse"),
    //         Err(..) => () // These paths should all fail to translate
    //     };
    // }

    #[test_case("md", "text/markdown", "/readme.md"; "Markdown file (not built-in)")]
    #[test_case("xml", "hej/mor", "/test-data/xml.xml"; "Xml file (overrides built-in)")]
    fn returns_expected_custom_mimetypes(file_type: &str, mime_type: &str, path: &str) {
        let conf = ServerConfiguration::new(PathBuf::new(), None, Some(vec![(file_type.to_owned(), mime_type.to_owned())]), None, false, None);
        let address = start_server(Some(conf));

        let req = format!("GET {path} HTTP/1.1\r\n\r\n");
        let response = call_server_and_read_response(address, &req);

        let mut lines = response.lines();

        let response_start_line = lines.next().expect("No lines");
        let content_type_header = lines
            .find(|l| l.starts_with("Content-Type")).expect("Content-Type header not found");

        let content_type = content_type_header.split(":").last().expect("Content-Type header invalid").trim();

        assert!(response_start_line.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(mime_type, content_type);
    }

    #[test]
    fn responds_to_get_request() {
        let address = start_server(None);
        let response = call_server_and_read_response(address, HTTP_REQ_GET_README_MD);
        
        let mut res_lines = response.lines();
        let response_start_line = res_lines.next().expect("No lines");
        let content_type_header = res_lines
            .find(|l| l.starts_with("Content-Type")).expect("Could not find content-type header");
        let content_length_header = res_lines
            .find(|l| l.starts_with("Content-Length")).expect("Could not find content-length header");
        let content_type = content_type_header.split(":")
            .last().expect("Content-Type header invalid")
            .trim();
        let content_length = content_length_header.split(":")
            .last().expect("Content-Length header invalid")
            .trim()
            .parse::<i32>().expect("Could not parse content-length as number");

        let file_length = fs::read_to_string("readme.md").expect("Could not read file").len();

        // check that we got a 200 ok
        assert_eq!("HTTP/1.1 200 OK", response_start_line);

        // check that our content-length matches the file itself
        assert_eq!(content_length as usize, file_length);

        // Mime type should also be included
        assert_eq!("text/plain", content_type);
    }

    #[test]
    fn returns_expected_405_method_not_allowed() {
        let address = start_server(None);

        let response = call_server_and_read_response(address, HTTP_REQ_POST);

        assert!(response.starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn connection_is_closed_after_reading_unpported_method() {
        let address = start_server(None);

        let client_handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();

            // post method is unsupported
            stream.write(HTTP_REQ_POST.as_bytes()).unwrap();
            let mut buf: [u8; 100] = [0;100];
            let read_c = stream.read(&mut buf).unwrap();

            // response message should be 405 method not allowed
            let str = String::from_utf8_lossy(&buf[0..read_c]).into_owned();

            // and if we try to continue using the socket, it should be flagged as closed
            let err_kind: ErrorKind;
            loop {
                match stream.write("x".as_bytes()) {
                    // connection does not close "instantly", so we might have some delay on this
                    Ok(..) => (),
                    Err(e) => {
                        // we should get this pretty fast however
                        err_kind = e.kind();
                        break;
                    }
                };
            };

            (str, err_kind)
        });

        let client_res = client_handle.join().unwrap();
        let e = client_res.1;

        assert!(client_res.0.starts_with("HTTP/1.1 405 Method Not Allowed"));
        // depending on how the connection is closed, it can become both reset or aborted
        assert!(e == ErrorKind::ConnectionReset || e == ErrorKind::ConnectionAborted);
    }

    #[test]
    fn can_not_use_globs_if_multiple_matched_files() {
        // We want to be deterministic if we also allow globbing
        let address = start_server(None);

        let response = call_server_and_read_response(address, HTTP_REQ_GET_CARGO_MULTIPLE_MATCH_GLOB_TEST);

        assert!(response.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn can_use_globs_to_match_to_filename() {
        let address = start_server(None);

        let response = call_server_and_read_response(address, HTTP_REQ_GET_README_GLOB_TEST);

        assert!(response.starts_with("HTTP/1.1 200"));
    }

    #[test_case("/", "readme.md"; "root")]
    #[test_case("/src/", "main.rs"; "sub folder with slash")]
    fn can_map_to_default_document(path: &str, default_doc: &str) {
        use std::env::current_dir;

        let default_docs = Some(vec![default_doc.to_owned()]);
        let conf = ServerConfiguration::new(current_dir().expect("Failed to read current dir"), default_docs, None, None, false, None);
        let address = start_server(Some(conf));

        let request = format!("GET {path} HTTP/1.1\r\n\r\n");
        let response = call_server_and_read_response(address, &request);

        assert!(response.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn returns_expected_404_not_found() {
        let address = start_server(None);

        let response = call_server_and_read_response(address, HTTP_REQ_GET_NON_EXISTENT_FILE);

        assert!(response.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn bad_request_status_code_if_incoming_msg_is_too_large_for_internal_stream_buffer() {
        let conf = ServerConfiguration::new(PathBuf::new(), None, None, Some(100), false, None);
        let address = start_server(Some(conf));

        let request = format!("GET / HTTP/1.1\r\nSome-Header: {}\r\n\r\n", "0123456789".repeat(100));
        let response = call_server_and_read_response(address, &request);

        println!("RESPONSE:\n{response}");

        assert!(response.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn returns_directory_listings() {
        use chunked_transfer::Decoder;
        
        let current_dir = std::env::current_dir().unwrap();
        let conf = ServerConfiguration::new(current_dir, None, None, None, true, None);
        let address = start_server(Some(conf));

        let client_handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write(HTTP_REQ_GET_SRC_DIRECTORY_FOR_LISTING.as_bytes()).unwrap();
            let mut buf = Vec::new();
            let read_c = stream.read_to_end(&mut buf).unwrap();
            Vec::from(&buf[0..read_c])
        });

        let response = client_handle.join().unwrap();
        let body_start = String::from_utf8_lossy(&response).find("\r\n\r\n").unwrap();

        let response_body = &response[body_start+4..];

        let mut decoder = Decoder::new(response_body);
        let mut decoded_body = String::new();
        decoder.read_to_string(&mut decoded_body).unwrap();

        // check that the output contains (some of) the relevant files
        assert!(["log.rs", "main.rs", "server.rs"].iter().all(|f| decoded_body.contains(f)));
    }

    #[test]
    fn can_reuse_connection_for_multiple_requests() {
        let address = start_server(None);

        let client_handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            // we're just splitting the request here for no real reason
            stream.write("GET /test-data/xml.xml HTTP/1.1\r\n".as_bytes()).unwrap();
            stream.write("Connection: keep-alive\r\n\r\n".as_bytes()).unwrap();
            // the exact size of the response, for both xml and txt files
            let mut buffer = [0; 101];
            stream.read_exact(&mut buffer).unwrap();
            let response_xml = String::from_utf8_lossy(&buffer).into_owned();
            // send second request using the same socket
            stream.write("GET /test-data/plain.txt HTTP/1.1\r\n\r\n".as_bytes()).unwrap();
            stream.read_exact(&mut buffer).unwrap();
            let response_txt = String::from_utf8_lossy(&buffer).into_owned();
            // give the connection time to shutdown
            thread::sleep(Duration::from_millis(100));
            // while im sure it's somewhat undefined and dependent on timing,
            // writing twice to the socket seems the most reliable way to see
            // a closed connection, on the second write.
            stream.write("GET ".as_bytes()).unwrap_or(0); // ignore this part
            // and this time we should get an actual error
            let write_result = stream.write("/test_data/xml.xml HTTP/1.1\r\n\r\n".as_bytes());
            (response_xml, response_txt, write_result)
        });

        let (response_xml, response_txt, write_result) = client_handle.join().unwrap();

        assert!(response_xml.starts_with("HTTP/1.1 200 OK"));
        assert!(response_txt.starts_with("HTTP/1.1 200 OK"));
        assert!(write_result.is_err());
        let err_kind = write_result.unwrap_err().kind();
        // connection error can be either kind
        assert!(err_kind == ErrorKind::ConnectionAborted || err_kind == ErrorKind::ConnectionReset);
    }

    #[test]
    fn returns_redirect_on_dir_access_without_slash() {
        let current_dir = std::env::current_dir().unwrap();
        let conf = ServerConfiguration::new(current_dir, Some(vec!["index.html".to_string()]), None, None, true, None);
        let address = start_server(Some(conf));

        // we should receive a redirect from "/test-data/axure" => "/test-data/axure/"
        let response = call_server_and_read_response(address, "GET /test-data/axure HTTP/1.1\n\n");

        let mut lines = response.lines();

        let response_start_line = lines.next().expect("No lines");
        let content_type_header = lines
            .find(|l| l.starts_with("Location")).expect("Location header not found");

        assert!(response_start_line.starts_with("HTTP/1.1 307"));
        assert!(content_type_header.contains("/test-data/axure/"));
    }

    #[test]
    fn does_not_return_anything_on_connection_timeout() {
        let current_dir = std::env::current_dir().unwrap();
        let conf = ServerConfiguration::new(current_dir, None, None, None, false, Some(200));
        let address = start_server(Some(conf));

        let client_handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let mut buf = Vec::new();
            let read_c = stream.read_to_end(&mut buf).unwrap();
            String::from_utf8_lossy(&buf[0..read_c]).into_owned()
        });

        let response = client_handle.join().unwrap();

        assert_eq!(response, "");
    }
}
