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
}

pub struct Server {
    conf: ServerConfiguration,
    address: SocketAddr,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    socket: Option<Socket>,
}

impl ServerConfiguration {
    pub fn new(www_root: PathBuf, default_documents: Option<Vec<String>>, mime_types: Option<Vec<(String, String)>>, buffer_size: Option<usize>, directory_browsing: bool) -> ServerConfiguration {
        ServerConfiguration {
            www_root,
            default_documents,
            mime_types,
            buffer_size: buffer_size.unwrap_or(10000),
            directory_browsing
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
    PathMetadataFailed,
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
                log(LogCategory::Warning, &status);
                status
            }
        } else {
            let status = format!("Failed to write headers to response");
            log(LogCategory::Warning, &status);
            status
        }
    } else {
        let status = format!("500 Internal Server Error");
        handle_http_error(stream, 500, "Internal Server Error", None);
        log(LogCategory::Info, &status);
        status
    }
}

fn handle_http_error(stream: &mut Stream, code: u32, body: &str, headers: Option<Vec<String>>) {
    let status = match code {
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
        log(LogCategory::Warning, &format!("Failed writing error response: {:?}", err))
    });
}

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

fn process_request(file_path: &PathBuf, conf: &ServerConfiguration) -> Result<RequestedFileInfo, Error> {
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
                match map_to_default_document(&file_path, &conf.default_documents, &conf.www_root) {
                    Some(p) => {
                        file_size = p.metadata()?.len();
                        file_path = p;
                        Ok(())
                    },
                    None => {
                        if conf.directory_browsing {
                            Err(Error::PathIsDirectory)
                        } else {
                            log(LogCategory::Info, "Path is directory");
                            Err(Error::PathMustBeFile)
                        }
                    }
                }
            } else {
                log(LogCategory::Info, "Path not handled");
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

            // We only want one match
            let single_match = glob_match_ok && matches.next().is_none();
            if single_match {
                // One matched file
                Ok(())
            } else if glob_match_ok {
                // We must have had multiple matches
                log(LogCategory::Info, &format!("Multiple files matched \"{}\": {}", file_path.to_string_lossy(), err));
                Err(Error::PathMustBeFile)
            } else {
                log(LogCategory::Info, &format!("Failed to read metadata for \"{}\": {}", file_path.to_string_lossy(), err));
                Err(Error::PathMetadataFailed)
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
    println!("CHUNK: {:?}", str);
    stream.write_all(str.as_bytes())?;
    Ok(())
}

fn process_directory_listing(path: &PathBuf, request_target: &Option<String>, stream: &mut Stream) -> Result<(), StreamError> {
    let dir = fs::read_dir(path).expect("path was not a directory");
    let initial = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html",
        "Transfer-Encoding: chunked",
        "",
        "6",
        "<ul>\r\n",
        ""
    ].join("\r\n");
    // todo this fails??
    // write_http_chunk(stream, "<ul>\r\n")?;
    stream.write_all(initial.as_bytes()).unwrap();
    for path in dir {
        let file_name_os = path.unwrap().file_name();
        let s = file_name_os.to_str().unwrap();
        let str = format!("<li><a href=\"{s}\">{s}</a></li>\r\n");
        let chunk = format!("{:x}\r\n{}\r\n", str.len(), str);
        stream.write_all(chunk.as_bytes()).unwrap();
    }
    let end = [
        "7",
        "</ul>\r\n",
        "0",
        "",
        ""
    ].join("\r\n");
    stream.write_all(end.as_bytes()).unwrap();
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
                        log(LogCategory::Warning, &format!("No mimetype for '{}'", ext));
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
                        match process_request(&file_path, &conf) {
                            Ok(file_info) => {
                                handle_response(&mut stream, &file_info);
                            },
                            Err(err) => {
                                match err {
                                    Error::PathIsDirectory => {
                                        // path is directory is only if directory_browsing is enabled
                                        assert!(conf.directory_browsing);
                                        if let Err(_e) = process_directory_listing(&file_path, &request.target, &mut stream) {
                                            // todo if we had an error while printing the listings, we probably also want to break
                                        }
                                    },
                                    _ => {
                                        log(LogCategory::Info, &format!("Error: {:?}", err));
                                        handle_http_error(&mut stream, 404, "Not Found", None);
                                    }
                                }
                            }
                        };
                    },
                    Err(err) => {
                        // todo: this possibly needs to be bad request?
                        // and we probably want to break the loop, closing the connection
                        handle_http_error(&mut stream, 404, "Not Found", None);
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
                        handle_http_error(&mut stream, 400, "", None);
                    },
                    HttpError::MethodNotSupported(..) => {
                        handle_http_error(&mut stream, 405, "", Some(["Allow: GET".to_owned()].to_vec()));
                    },
                    HttpError::StreamError(StreamError::ConnectionTimeout) |
                    HttpError::StreamError(StreamError::ConnectionClosed) | 
                    HttpError::StreamError(StreamError::ConnectionReset) => {
                        log(LogCategory::Info, &format!("Connection error: {:?}", err));
                    }
                    _ => {
                        println!("handle_connection:Err:{:?}", err);
                        handle_http_error(&mut stream, 500, "", None);
                    }
                };
                // close connection by returning from function, causing
                // the thread to exit and the connection to be dropped
                break;
            }
        }
    }
}

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
                            log(LogCategory::Error, &format!("{}", ee));
                        },
                        _ => ()
                    }
                }
            }
        },
        None => {
            thread::spawn(move || {
                handle_connection(stream, conf);
            });
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
        let socket = bind_server_socket(self.address, 2000)?;
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
        let conf = match conf {
            Some(c) => c,
            None => ServerConfiguration::new(PathBuf::new(), None, None, None, false)
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
    #[test_case("xml", "hej/mor", "/test_data/xml.xml"; "Xml file (overrides built-in)")]
    fn returns_expected_custom_mimetypes(file_type: &str, mime_type: &str, path: &str) {
        let conf = ServerConfiguration::new(PathBuf::new(), None, Some(vec![(file_type.to_owned(), mime_type.to_owned())]), None, false);
        let address = start_server(Some(conf));

        let req = format!("GET {path} HTTP/1.1\r\n\r\n");
        let response = call_server_and_read_response(address, &req);

        println!("{:?}", response);

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
    #[test_case("/src", "main.rs"; "sub folder no slash")]
    fn can_map_to_default_document(path: &str, default_doc: &str) {
        use std::env::current_dir;

        let default_docs = Some(vec![default_doc.to_owned()]);
        let conf = ServerConfiguration::new(current_dir().expect("Failed to read current dir"), default_docs, None, None, false);
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
        let conf = ServerConfiguration::new(PathBuf::new(), None, None, Some(100), false);
        let address = start_server(Some(conf));

        let request = format!("GET / HTTP/1.1\r\nSome-Header: {}\r\n\r\n", "0123456789".repeat(100));
        let response = call_server_and_read_response(address, &request);

        println!("RESPONSE:\n{response}");

        assert!(response.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn returns_directory_listings() {
        use chunked_transfer::Decoder;
        
        let conf = ServerConfiguration::new(PathBuf::new(), None, None, None, true);
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
}
