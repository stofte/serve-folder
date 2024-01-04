use std::env::current_dir;
use std::io::{BufReader, BufWriter, Read, Write, BufRead};
use std::fs::File;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use native_tls::{TlsAcceptor, HandshakeError};
use phf::phf_map;
use crate::log::{LogCategory, log};

pub fn run_server(listener: TcpListener, tls_acceptor: &Option<Arc<TlsAcceptor>>) {
    for stream in listener.incoming() {
        println!("Incoming stream!");
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
    use dunce::canonicalize;

    let buf_reader = BufReader::new(&mut stream);
    if let Some(Ok(line)) = buf_reader.lines().nth(0) {
        if let Some(request_info) = translate_path(&line) {
            let path = request_info.mapped_path;
            let mut writer = BufWriter::new(stream);
            let mut file_size = 0;
            let mut norm_path = path.to_string_lossy();
            let mut response_status: String = String::from("");
            let file_ok = match std::fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        file_size = metadata.len();
                        norm_path = String::from(canonicalize(&path).expect("Failed to canonicalize path").to_string_lossy()).into();
                        true
                    } else {
                        log(LogCategory::Info, &format!(
                            "Path is not a file. is_dir={}, is_symlink={}",
                            metadata.is_dir(),
                            metadata.is_symlink()
                        ));
                        false
                    }
                },
                Err(err) => {
                    log(LogCategory::Info, &format!("Failed to read metadata: {}", err));
                    false
                }
            };
            match file_ok {
                true => {
                    let f_wrapped = File::open(&path);
                    if f_wrapped.is_ok() {
                        // File could be opened
                        let f = f_wrapped.unwrap();
                        let mut br = BufReader::new(f);
                        let lines = [
                            "HTTP/1.1 200 OK",
                            "Cache-Control: no-store",
                            &format!("Content-Type: {}", get_mimetype(&path)),
                            &format!("Content-Length: {}\r\n\r\n", file_size),
                        ].join("\r\n");

                        // We dump the file directly into the response.
                        // Ideally we would ensure crlf as newlines, etc.
                        if writer.write_all(lines.as_bytes()).is_ok() {
                            // All headers written, try to write file
                            if std::io::copy(&mut br, &mut writer).is_ok() {
                                response_status = format!("{} ({} bytes)", &norm_path, file_size);
                            } else {
                                log(LogCategory::Warning, &format!("Failed to write contents to response"));
                            }
                        } else {
                            log(LogCategory::Info, &format!("Failed to write headers to response"));
                        }
                    } else {
                        if !writer.write_all("HTTP/1.1 500 Internal Server Error\n".as_bytes()).is_ok() {
                            log(LogCategory::Info, &format!("Failed to write to response"));
                        }
                    }
                },
                false => {
                    writer.write_all("HTTP/1.1 404 Not Found\n".as_bytes()).expect("Could not write");
                    response_status = String::from("404 Not Found");
                }
            }
            log(LogCategory::Info, &format!("Request {} => {}", &request_info.method, response_status));
        } else {
            log(LogCategory::Info, &format!("Unsupported method"));
        }
    }
}

const GET_VERB: &str = "GET ";
const HTTP_VER: &str = " HTTP/1.1";

struct RequestInfo {
    method: String,
    mapped_path: PathBuf,
}

impl RequestInfo {
    fn new(method: String, path: PathBuf) -> RequestInfo {
        RequestInfo {
            method: method,
            mapped_path: path
        }
    }
}

fn translate_path(line: &str) -> Option<RequestInfo> {
    if line.starts_with(GET_VERB) && line.ends_with(HTTP_VER) {
        // Remove verb + HTTP version
        let mut path = String::from(&line[GET_VERB.len()..]);
        path.truncate(path.len() - HTTP_VER.len());

        // Format into a URL, so we can use parsing from std lib.
        // This also seems to prevent basic path traversel attempts.
        let dummyurl = String::from("http://localhost/") + &path;
        let cur_dir = current_dir().expect("no path?");

        return match url::Url::parse(&dummyurl) {
            Ok(url) => {
                let path_buf = std::path::Path::new(&cur_dir)
                    .join(".".to_owned() + std::path::MAIN_SEPARATOR_STR)
                    .join(".".to_owned() + &url.path().replace("/", "\\"));
                Some(RequestInfo::new(String::from("GET"), path_buf))
            },
            Err(_) => None
        }
    }
    None
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
};

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
    fn can_translate_paths() {
        let result = translate_path(&"GET /foo.txt HTTP/1.1").unwrap();
        let pb = current_dir().unwrap().join("foo.txt");
        assert_eq!(result.mapped_path, pb);
    }
 
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

    #[test_case("../../../foo"; "Regular")]
    #[test_case("..\\..\\..\\foo"; "Regular 2nd")]
    #[test_case("%2e%2e%2ffoo"; "Encoded")]
    #[test_case("..%c0%affoo"; "Encoded 2nd")]
    fn handles_path_traversel_attempts(str: &str) {
        let request_header = format!("GET {} HTTP/1.1", str);
        let result = translate_path(&request_header).unwrap();
        assert!(result.mapped_path.starts_with(current_dir().unwrap()));
    }
}
