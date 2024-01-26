use std::io::{BufReader, BufWriter, Read, Write, BufRead};
use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use native_tls::{TlsAcceptor, HandshakeError};
use phf::phf_map;
use thiserror::Error;
use crate::log::{LogCategory, log};
use crate::request::HttpRequest;

const GET_VERB: &str = "GET ";
const HTTP_VER: &str = " HTTP/1.1";
const TCP_BUFFER_SIZE: usize = 30;

#[derive(Clone)]
pub struct ServerConfiguration {
    pub www_root: PathBuf,
    default_documents: Option<Vec<String>>,
    mime_types: Option<Vec<(String, String)>>,
}

impl ServerConfiguration {
    pub fn new(www_root: PathBuf, default_documents: Option<Vec<String>>, mime_types: Option<Vec<(String, String)>>) -> ServerConfiguration {
        ServerConfiguration {
            www_root,
            default_documents,
            mime_types,
        }
    }
}

#[derive(Error, Debug)]
enum Error {
    #[error("Unsupported method")]
    UnsupportedMethod,
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

pub fn run_server(listener: TcpListener, tls_acceptor: &Option<Arc<TlsAcceptor>>, conf: ServerConfiguration) {
    let conf_arc = Arc::new(conf);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => setup_connection(stream, &tls_acceptor, conf_arc.clone()),
            Err(_) => () // connection failed?
        }
    }
}

fn setup_connection(stream: TcpStream, tls_acceptor: &Option<Arc<TlsAcceptor>>, conf: Arc<ServerConfiguration>) {
    use std::thread;
    match &tls_acceptor {
        Some(acceptor) => {
            match acceptor.accept(stream) {
                Ok(stream) => {
                    let s = Arc::new(Mutex::new(stream));
                    thread::spawn(move || handle_connection(&s, &conf));
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
                let s = Arc::new(Mutex::new(stream));
                handle_connection(&s, &conf);
            });
        }
    }
}

fn handle_connection(stream: &Arc<Mutex<impl Read + Write>>, conf: &ServerConfiguration) {
    use std::time::Instant;

    let mut last_data = Instant::now();
    let mut req = HttpRequest::new();
    let mut data = [0; TCP_BUFFER_SIZE];
    loop {
        let res = stream.lock().unwrap().read(&mut data);
        match res {
            Ok(read_count) => {
                if read_count == 0 {
                    break;
                } else {
                    last_data = Instant::now();
                    let done = req.read_stream(&data, read_count);
                    if done {
                        // parsed full http request here
                        println!("{:?} received:\n{:?}", std::thread::current().id(), req);
                        // figure out what file to return
                        match process_request2(&req, conf) {
                            Ok(file_info) => {
                                handle_response2(&stream, &file_info, conf);
                            },
                            Err(err) => {
                                log(LogCategory::Info, &format!("Error: {:?}", err));
                                handle_http_error(&stream, 404, "Not Found");
                            }
                        };
                        // TODO: if we did not receive "Connection: Keep-Alive", 
                        // we should also break here, and close down the connection
                        if req.connectionKeepAlive() {
                            req = HttpRequest::new();
                            continue;
                        } else {
                            break;
                        }
                    }
                }
            },
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::TimedOut => {
                        if last_data.elapsed().as_secs() > 10 {
                            println!("No data in 10 seconds, termining: {:?} >> {:?}", last_data, Instant::now());
                            break;
                        }
                    },
                    _ => {
                        println!("Other: read err: {:?}", e);
                        break;
                    }
                }
            }
        };
    }
}

fn handle_response2(writer: &Arc<Mutex<impl Write>>, request_info: &RequestedFileInfo, conf: &ServerConfiguration) -> String {
    let path = &request_info.file_path;
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
        if writer.lock().unwrap().write_all(lines.as_bytes()).is_ok() {
            // All headers written, try to write file
            let mut foo = writer.lock().unwrap();
            if std::io::copy(&mut br, &mut *foo).is_ok() {
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
        handle_http_error(writer, 500, "Internal Server Error");
        log(LogCategory::Info, &status);
        status
    }
}

fn handle_http_error(writer: &Arc<Mutex<impl Write>>, code: u32, body: &str) {
    let status = match code {
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error"
    };
    let header = &format!("HTTP/1.1 {} {}", code, status);
    let content_type = "Content-Type: text/plain";
    let content_length = &format!("Content-Length: {}", body.len());

    let lines = [
        header,
        content_type,
        content_length,
        "",
        body
    ].join("\r\n");

    writer.lock().unwrap().write_all(lines.as_bytes()).unwrap_or_else(|err| {
        log(LogCategory::Warning, &format!("Failed writing error response: {}", err))
    });
}

fn process_request2(request: &HttpRequest, conf: &ServerConfiguration) -> Result<RequestedFileInfo, Error> {
    use std::path::MAIN_SEPARATOR_STR;
    use normpath::PathExt;
    use glob::glob;
    
    let target_path = request.target.as_ref().unwrap();
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
                match map_to_default_document(&file_path, &conf.default_documents, &conf.www_root) {
                    Some(p) => {
                        file_size = p.metadata()?.len();
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

fn process_request(line: &str, conf: &ServerConfiguration) -> Result<RequestedFileInfo, Error> {
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
                match map_to_default_document(&file_path, &conf.default_documents, &conf.www_root) {
                    Some(p) => {
                        file_size = p.metadata()?.len();
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

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fs};
    use test_case::test_case;
    use super::*;

    fn wrap_inp_vec(vec: VecDeque<u8>) -> Arc<Mutex<VecDeque<u8>>> {
        Arc::new(Mutex::new(vec))
    }

    // These tests generally assume that the tests are run with project root as the current_dir.
 
    #[test]
    fn returns_expected_200_ok_response() {
        // Check that:
        // 1. we got an 200 ok response
        // 2. mimetype is as expected (here, text/plain)
        // 3. content-length is as expected
       
        let conf = ServerConfiguration::new(PathBuf::new(), None, None);
        let inp = wrap_inp_vec(VecDeque::from(b"GET /readme.md HTTP/1.1\r\n\r\n".to_owned()));

        handle_connection(&inp, &conf);
        let veq = inp.lock().unwrap().to_owned();

        // parse out the response headers, etc
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
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
    fn can_use_globs_to_match_to_filename() {
        let conf = ServerConfiguration::new(PathBuf::new(), None, None);
        let inp = wrap_inp_vec(VecDeque::from(b"GET /readme HTTP/1.1\r\n\r\n".to_owned()));

        handle_connection(&inp, &conf);

        let veq = inp.lock().unwrap().to_owned();
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        
        assert!(response.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn can_not_use_globs_if_multiple_matched_files() {
        // We want to be deterministic if we also allow globbing

        let conf = ServerConfiguration::new(PathBuf::new(), None, None);
        let inp = wrap_inp_vec(VecDeque::from(b"GET /Cargo HTTP/1.1\r\n\r\n".to_owned()));

        handle_connection(&inp, &conf);
        
        let veq = inp.lock().unwrap().to_owned();
        let response = String::from_utf8(veq.into()).expect("Failed to read response");
        
        assert!(response.starts_with("HTTP/1.1 404"));
    }

    // #[test]
    // fn returns_expected_405_method_not_allowed() {
    //     let conf = ServerConfiguration::new(PathBuf::new(), None, None);
    //     let mut veq = VecDeque::from(b"PUT /readme.md HTTP/1.1".to_owned());

    //     handle_response(&mut veq, &conf);

    //     let response = String::from_utf8(veq.into()).expect("Failed to read response");
    //     assert!(response.starts_with("HTTP/1.1 405"));
    // }

    // #[test]
    // fn returns_expected_404_not_found() {
    //     let conf = ServerConfiguration::new(PathBuf::new(), None, None);
    //     let mut veq = VecDeque::from(b"GET /some_file_not_here HTTP/1.1".to_owned());

    //     handle_response(&mut veq, &conf);

    //     let response = String::from_utf8(veq.into()).expect("Failed to read response");
    //     assert!(response.starts_with("HTTP/1.1 404"));
    // }

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

    // #[test_case("/", "readme.md"; "root")]
    // #[test_case("/src/", "main.rs"; "sub folder with slash")]
    // #[test_case("/src", "main.rs"; "sub folder no slash")]
    // fn can_map_to_default_document(path: &str, default_doc: &str) {
    //     use std::env::current_dir;
        
    //     let req = format!("GET {path} HTTP/1.1");
    //     let mut veq = VecDeque::from(req.as_bytes().to_owned());
    //     let default_docs = Some(vec![default_doc.to_owned()]);
    //     let conf = ServerConfiguration::new(current_dir().expect("Failed to read current dir"), default_docs, None);
        
    //     handle_response(&mut veq, &conf);

    //     let response = String::from_utf8(veq.into()).expect("Failed to read response");

    //     assert!(response.starts_with("HTTP/1.1 200"));
    // }

    // #[test_case("md", "text/markdown", "/readme.md"; "Markdown file (not built-in)")]
    // #[test_case("xml", "hej mor", "/test_data/xml.xml"; "Xml file (overrides built-in)")]
    // fn returns_expected_custom_mimetypes(file_type: &str, mime_type: &str, path: &str) {
    //     let req = format!("GET {path} HTTP/1.1");
    //     let conf = ServerConfiguration::new(PathBuf::new(), None, Some(vec![(file_type.to_owned(), mime_type.to_owned())]));
    //     let mut socket = VecDeque::from(req.as_bytes().to_owned());

    //     handle_response(&mut socket, &conf);

    //     let response = String::from_utf8(socket.into()).expect("Failed to read response");
    //     let mut lines = response.lines();

    //     let response_start_line = lines.next().expect("No lines");
    //     let content_type_header = lines
    //         .find(|l| l.starts_with("Content-Type")).expect("Content-Type header not found");

    //     let content_type = content_type_header.split(":").last().expect("Content-Type header invalid").trim();

    //     assert!(response_start_line.starts_with("HTTP/1.1 200 OK"));
    //     assert_eq!(mime_type, content_type);
    // }
}
