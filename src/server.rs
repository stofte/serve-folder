use std::env::current_dir;
use std::io::{BufReader, BufWriter, Read, Write, BufRead};
use std::fs::File;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use native_tls::{TlsAcceptor, HandshakeError};
use phf::phf_map;
use crate::log::{LogCategory, log};

const GET_VERB: &str = "GET ";
const HTTP_VER: &str = " HTTP/1.1";

pub struct ServerConfiguration {
    default_documents: Option<Vec<String>>,
    mime_types: Option<Vec<(String, String)>>,
}

impl ServerConfiguration {
    pub fn new(default_documents: Option<Vec<String>>, mime_types: Option<Vec<(String, String)>>) -> ServerConfiguration {
        ServerConfiguration {
            default_documents,
            mime_types,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Error {
    UnsupportedMethod,
    PathParsingFailed,
    PathMustBeFile,
    PathMetadataFailed,
}

struct RequestInfo {
    method: String,
    path: String,
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

pub fn run_server(listener: TcpListener, tls_acceptor: &Option<Arc<TlsAcceptor>>, conf: ServerConfiguration) {
    for stream in listener.incoming() {
        handle_connection(stream, &tls_acceptor, &conf);
    }
}

fn handle_connection(stream: Result<impl Read + Write, std::io::Error>, tls_acceptor: &Option<Arc<TlsAcceptor>>, conf: &ServerConfiguration) {
    match stream {
        Ok(stream) => {
            match &tls_acceptor {
                Some(acceptor) => {
                    match acceptor.accept(stream) {
                        Ok(stream) => handle_response(stream, &conf),
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
                    handle_response(stream, &conf);
                }
            }
        }
        Err(_) => { /* connection failed */ }
    }
}

fn handle_response(mut stream: impl Read + Write, conf: &ServerConfiguration) {
    let buf_reader = BufReader::new(&mut stream);
    if let Some(Ok(line)) = buf_reader.lines().nth(0) {
        let mut writer = BufWriter::new(stream);
        let response_status = match process_request(&line, conf) {
            Ok(request_info) => {
                let path = request_info.file_path;
                let f_wrapped = File::open(&path);
                if f_wrapped.is_ok() {
                    // File could be opened
                    let f = f_wrapped.unwrap();
                    let mut br = BufReader::new(f);
                    let lines = [
                        "HTTP/1.1 200 OK",
                        "Cache-Control: no-store",
                        &format!("Content-Type: {}", &request_info.mime_type),
                        &format!("Content-Length: {}\r\n\r\n", &request_info.file_size),
                    ].join("\r\n");

                    // We dump the file directly into the response.
                    // Ideally we would ensure crlf as newlines, etc.
                    if writer.write_all(lines.as_bytes()).is_ok() {
                        // All headers written, try to write file
                        if std::io::copy(&mut br, &mut writer).is_ok() {
                            format!("{} ({} bytes)", &path.to_string_lossy(), request_info.file_size)
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
                    handle_http_error(&mut writer, 500, "Internal Server Error");
                    log(LogCategory::Info, &status);
                    status
                }
            },
            Err(Error::UnsupportedMethod) => {
                log(LogCategory::Info, &format!("Unsupported method"));
                handle_http_error(&mut writer, 405, "Method Not Allowed");
                String::from("405 Method Not Allowed")
            }
            Err(err) => {
                log(LogCategory::Info, &format!("Error: {:?}", err));
                handle_http_error(&mut writer, 404, "Not Found");
                String::from("404 Not Found")
            }
        };
        log(LogCategory::Info, &format!("Request {} => {}", &line, response_status));
    }
}

fn handle_http_error(writer: &mut BufWriter<impl Write>, code: u32, body: &str) {
    let status = match code {
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error"
    };
    let header = format!("HTTP/1.1 {} {}", code, status);
    let content_type = "Content-Type: text/plain".to_string();
    let content_length = format!("Content-Length: {}", body.len());

    let lines = [header,
        content_type,
        content_length,
        "".to_string(),
        body.to_string()
    ].join("\r\n");

    writer.write_all(lines.as_bytes()).expect("Could not write");
}

fn process_request(line: &str, conf: &ServerConfiguration) -> Result<RequestInfo, Error> {
    use std::path::MAIN_SEPARATOR_STR;
    use normpath::PathExt;
    use glob::glob;

    if !line.starts_with(GET_VERB) || !line.ends_with(HTTP_VER) {
        return Err(Error::UnsupportedMethod);
    }

    // Remove verb + HTTP version
    let line_end = line.len() - HTTP_VER.len();
    let path = line[GET_VERB.len()..line_end].to_string();
    
    // File path mapping algorithm:
    // Following steps are always taken:
    // - Validate the path starts with "/"
    // - Normalizing path by passing it through rusts Url::parse()
    // - Read the url.path() component, stripping the initial "/"
    // - Transform to a fs path, by constructing it via "current_dir\.\path_from_url"
    // We can now determine what file to return:
    // - If we have a file we are done, else
    // - If the path is a folder, check if any default docs exists at "path\default_doc", else
    // - If the path does not exist, check if any exists at "path.*"
    // - Return not found

    if !path.starts_with("/") {
        return Err(Error::PathParsingFailed);
    }
    
    let parse_url = String::from("http://localhost") + &path;
    let cur_dir = current_dir().expect("no current_dir");
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
    
    let mut file_size = 0;
    let mut file_path = fs_path.into_path_buf();

    match std::fs::metadata(&file_path) {
        Ok(metadata) => {
            if metadata.is_file() {
                // All is good, direct file hit
                file_size = metadata.len();
                Ok(())
            } else if metadata.is_dir() {
                // Check if we have a default doc to return instead
                match map_to_default_document(&file_path, &conf.default_documents) {
                    Some(p) => {
                        file_size = p.metadata().expect("File metadata failed").len();
                        file_path = p;
                        Ok(())
                    },
                    None => {
                        log(LogCategory::Info, "Path is directory");
                        Err(Error::PathMustBeFile)
                    }
                }
            } else {
                log(LogCategory::Info, "Path not handled");
                Err(Error::PathMustBeFile)
            }
        },
        Err(err) => {
            // Nothing was found, see if a glob can find the file regardle
            let mut matches = glob(&format!("{}.*", file_path.to_string_lossy()))
                .expect("Failed to glob pattern");
            
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

    Ok(RequestInfo {
        method: "GET".to_string(),
        path: path.to_string(),
        mime_type: get_mimetype(&file_path).to_string(),
        file_size: file_size,
        file_path: file_path,
    })
}

fn map_to_default_document(path: &Path, default_documents: &Option<Vec<String>>) -> Option<PathBuf> {
    if let Some(doclist) = default_documents {
        let base = current_dir().expect("Could not find root").join(&path);
        if let Some(exists) = doclist.iter().find(|f| base.join(f).is_file()) {
            return Some(path.to_owned().join(exists));
        }
    }
    None
}

fn get_mimetype(path: &PathBuf) -> &str {
    match path.extension() {
        Some(val) => {
            let ext = val.to_string_lossy().to_string().to_lowercase();
            match MIMETYPES.get(&ext) {
                Some(mime) => mime,
                None => {
                    log(LogCategory::Warning, &format!("No mimetype for '{}'", ext));
                    "text/plain"
                }
            }
        }
        None => "text/plain"
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fs};
    use test_case::test_case;
    use super::*;

    // These tests generally assume that the tests are run with project root as the current_dir.
 
    #[test]
    fn returns_expected_200_ok_response() {
        // Check that:
        // 1. we got an 200 ok response
        // 2. mimetype is as expected (here, text/plain)
        // 3. content-length is as expected
        
        let conf = ServerConfiguration::new(None, None);
        let mut veq = VecDeque::from(b"GET /readme.md HTTP/1.1".to_owned());

        handle_response(&mut veq, &conf);

        // parse out the response headers, etc
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        let mut res_lines = response.lines();

        let response_start_line = res_lines.next().expect("No lines");
        let content_length_header = res_lines
            .find(|l| l.starts_with("Content-Length")).expect("Could not find content-length header");
        let content_length = content_length_header.split(":")
            .last().expect("Incorrect header format")
            .trim()
            .parse::<i32>().expect("Could not parse content-length as number");

        let file_length = fs::read_to_string("readme.md").expect("Could not read file").len();

        // check that we got a 200 ok
        assert_eq!("HTTP/1.1 200 OK", response_start_line);

        // check that our content-length matches the file itself
        assert_eq!(content_length as usize, file_length);
    }

    #[test]
    fn can_use_globs_to_match_to_filename() {
        let conf = ServerConfiguration::new(None, None);
        let mut veq = VecDeque::from(b"GET /readme HTTP/1.1".to_owned());

        handle_response(&mut veq, &conf);
        
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        
        assert!(response.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn can_not_use_globs_if_multiple_matched_files() {
        // We want to be deterministic if we also allow globbing

        let conf = ServerConfiguration::new(None, None);
        let mut veq = VecDeque::from(b"GET /Cargo HTTP/1.1".to_owned());

        handle_response(&mut veq, &conf);
        
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        
        assert!(response.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn returns_expected_405_method_not_allowed() {
        let conf = ServerConfiguration::new(None, None);
        let mut veq = VecDeque::from(b"PUT /readme.md HTTP/1.1".to_owned());

        handle_response(&mut veq, &conf);

        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        assert!(response.starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn returns_expected_404_not_found() {
        let conf = ServerConfiguration::new(None, None);
        let mut veq = VecDeque::from(b"GET /some_file_not_here HTTP/1.1".to_owned());

        handle_response(&mut veq, &conf);

        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        assert!(response.starts_with("HTTP/1.1 404"));
    }

    #[test_case("../../../foo"; "Regular")]
    #[test_case("..\\..\\..\\foo"; "Regular 2nd")]
    #[test_case("%2e%2e%2ffoo"; "Encoded")]
    #[test_case("..%c0%affoo"; "Encoded 2nd")]
    fn handles_path_traversel_attempts(str: &str) {
        let conf = ServerConfiguration::new(None, None);
        let request_header = format!("GET {} HTTP/1.1", str);
        match process_request(&request_header, &conf) {
            Ok(..) => panic!("Request path should not parse"),
            Err(..) => () // These paths should all fail to translate
        };
    }

    #[test_case("/", "readme.md"; "root")]
    #[test_case("/src/", "main.rs"; "sub folder with slash")]
    #[test_case("/src", "main.rs"; "sub folder no slash")]
    fn can_map_to_default_document(path: &str, default_doc: &str) {
        let req = format!("GET {path} HTTP/1.1");
        let mut veq = VecDeque::from(req.as_bytes().to_owned());
        let default_docs = Some(vec![default_doc.to_string()]);
        let conf = ServerConfiguration::new(default_docs, None);
        
        handle_response(&mut veq, &conf);

        let response = String::from_utf8(veq.into()).expect("Failed to read response");

        assert!(response.starts_with("HTTP/1.1 200"));
    }
}
