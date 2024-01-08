use std::env::current_dir;
use std::io::{BufReader, BufWriter, Read, Write, BufRead};
use std::fs::File;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use native_tls::{TlsAcceptor, HandshakeError};
use phf::phf_map;
use crate::log::{LogCategory, log};

#[derive(Debug, PartialEq)]
pub enum Error {
    UnsupportedMethod,
    PathParsingFailed,
    PathMustBeFile,
    PathMetadataFailed,
}

pub fn run_server(listener: TcpListener, tls_acceptor: &Option<Arc<TlsAcceptor>>) {
    for stream in listener.incoming() {
        handle_connection(stream, &tls_acceptor);
    }
}

fn handle_connection(stream: Result<impl Read + Write, std::io::Error>, tls_acceptor: &Option<Arc<TlsAcceptor>>) {
    match stream {
        Ok(stream) => {
            match &tls_acceptor {
                Some(acceptor) => {
                    match acceptor.accept(stream) {
                        Ok(stream) => handle_response(stream),
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
                    handle_response(stream);
                }
            }
        }
        Err(_) => { /* connection failed */ }
    }
}

fn handle_response(mut stream: impl Read + Write) {
    let buf_reader = BufReader::new(&mut stream);
    if let Some(Ok(line)) = buf_reader.lines().nth(0) {
        let mut writer = BufWriter::new(stream);
        let response_status = match translate_path(&line) {
            Ok(request_info) => {
                let path = request_info.mapped_path;
                let f_wrapped = File::open(&path);
                if f_wrapped.is_ok() {
                    // File could be opened
                    let f = f_wrapped.unwrap();
                    let mut br = BufReader::new(f);
                    let lines = [
                        "HTTP/1.1 200 OK",
                        "Cache-Control: no-store",
                        &format!("Content-Type: {}", get_mimetype(&path)),
                        &format!("Content-Length: {}\r\n\r\n", &request_info.file_size),
                    ].join("\r\n");

                    // We dump the file directly into the response.
                    // Ideally we would ensure crlf as newlines, etc.
                    if writer.write_all(lines.as_bytes()).is_ok() {
                        // All headers written, try to write file
                        if std::io::copy(&mut br, &mut writer).is_ok() {
                            format!("{} ({} bytes)", &path, request_info.file_size)
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

const GET_VERB: &str = "GET ";
const HTTP_VER: &str = " HTTP/1.1";

struct RequestInfo {
    method: String,
    path: String,
    mapped_path: String,
    file_size: u64
}

impl RequestInfo {
    fn new(method: String, path: String, mapped_path: String, file_size: u64) -> RequestInfo {
        RequestInfo {
            method: method,
            path: path,
            mapped_path: mapped_path,
            file_size: file_size
        }
    }
}

fn translate_path(line: &str) -> Result<RequestInfo, Error> {
    use normpath::PathExt;
    use glob::glob;

    if line.starts_with(GET_VERB) && line.ends_with(HTTP_VER) {
        // Remove verb + HTTP version
        let mut path = String::from(&line[GET_VERB.len()..]);
        path.truncate(path.len() - HTTP_VER.len());

        // Format into a URL, so we can use parsing from std lib.
        // This also seems to prevent basic path traversel attempts.
        let dummyurl = String::from("http://localhost/") + &path;
        let cur_dir = current_dir().expect("no current_dir");

        let mapped_path = match url::Url::parse(&dummyurl) {
            Ok(url) => {
                let path_buf = std::path::Path::new(&cur_dir)
                    .join(".".to_owned() + std::path::MAIN_SEPARATOR_STR)
                    .join(".".to_owned() + &url.path().replace("/", "\\"))
                    .normalize_virtually();
                match path_buf {
                    Ok(v) => Ok(v),
                    Err(..) => Err(Error::PathParsingFailed)
                }
            },
            Err(_) => Err(Error::PathParsingFailed)
        }?;

        let mut mapped_path = String::from(mapped_path.as_path().to_string_lossy());

        let method = String::from("GET");
        let mut file_size = 0;

        match std::fs::metadata(&mapped_path) {
            Ok(metadata) => {
                println!("OK ARM");
                if metadata.is_file() {
                    file_size = metadata.len();
                    Ok(())
                } else {
                    log(LogCategory::Info, &format!(
                        "Path is not a file. is_dir={}, is_symlink={}",
                        metadata.is_dir(),
                        metadata.is_symlink()
                    ));
                    Err(Error::PathMustBeFile)
                }
            },
            Err(err) => {
                // see if we can find it using globbing?
                let mut matches = glob(&format!("{}.*", mapped_path))
                    .expect("Failed to glob pattern");
                
                let glob_match_ok = match matches.next() {
                    Some(file) => {
                        match file {
                            Ok(p) => {
                                match std::fs::metadata(&p) {
                                    Ok(metadata) => {
                                        if metadata.is_file() {
                                            file_size = metadata.len();
                                            mapped_path = String::from(p.to_string_lossy());
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
                let single_match = glob_match_ok && matches.next().is_none();
                if single_match {
                    Ok(())
                } else {
                    log(LogCategory::Info, &format!("Failed to read metadata for \"{}\": {}", mapped_path, err));
                    Err(Error::PathMetadataFailed)
                }
            }
        }?;

        return Ok(RequestInfo::new(method, path, mapped_path, file_size));
    }
    Err(Error::UnsupportedMethod)
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

fn get_mimetype(path: &str) -> &str {
    let p: PathBuf = path.into();
    match p.extension() {
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
        
        let mut veq = VecDeque::from(b"GET /readme.md HTTP/1.1".to_owned());

        handle_response(&mut veq);

        // parse out the response headers, etc
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        println!("--{}--", response);
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
        let mut veq = VecDeque::from(b"GET /readme HTTP/1.1".to_owned());

        handle_response(&mut veq);
        
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        
        assert!(response.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn can_not_use_globs_if_multiple_matched_files() {
        // We want to be deterministic if we also allow globbing
        let mut veq = VecDeque::from(b"GET /Cargo HTTP/1.1".to_owned());

        handle_response(&mut veq);
        
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        
        assert!(response.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn returns_expected_405_method_not_allowed() {
        let mut veq = VecDeque::from(b"PUT /readme.md HTTP/1.1".to_owned());

        handle_response(&mut veq);

        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        assert!(response.starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn returns_expected_404_not_found() {
        let mut veq = VecDeque::from(b"GET /some_file_not_here HTTP/1.1".to_owned());

        handle_response(&mut veq);

        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        assert!(response.starts_with("HTTP/1.1 404"));
    }

    #[test_case("../../../foo"; "Regular")]
    #[test_case("..\\..\\..\\foo"; "Regular 2nd")]
    #[test_case("%2e%2e%2ffoo"; "Encoded")]
    #[test_case("..%c0%affoo"; "Encoded 2nd")]
    fn handles_path_traversel_attempts(str: &str) {
        let request_header = format!("GET {} HTTP/1.1", str);
        match translate_path(&request_header) {
            Ok(..) => panic!("Request path should not parse"),
            Err(..) => () // These paths should all fail to translate
        };
    }
}
