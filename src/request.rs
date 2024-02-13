use crate::misc::{HttpError, HttpHeader, HttpMethod, HttpVersion};

#[derive(Debug)]
pub struct HttpRequestOld {
    method: Option<HttpMethod>,
    pub target: Option<String>,
    protocol_version: Option<HttpVersion>,
    content_length: Option<u64>,
    headers: Vec<HttpHeader>,
    head_done: bool,
    buffer: Vec<u8>,
    done: bool
}

impl HttpRequestOld {
    pub fn new() -> HttpRequestOld {
        HttpRequestOld {
            method: None,
            target: None,
            protocol_version: None,

            content_length: None,
            headers: vec![],
            head_done: false,

            done: false,
            buffer: vec![],
        }
    }

    pub fn connection_keep_alive(&self) -> bool {
        if let Some(..) = self.headers.iter().find(|x| x.name == "connection") {
            true
        } else {
            false
        }
    }

    pub fn read_stream(&mut self, data: &[u8], length: usize) -> bool {
        let mut from = 0;
        loop {
            if self.head_done {
                // If headers have all been read, we stuff the rest
                // into the buffer until we have read content-length of bytes.
                self.buffer.extend_from_slice(&data[from..length]);
                break;
            } else {
                match find_newline_index(&data, from, length) {
                    Some((start, end)) => {
                        self.buffer.extend_from_slice(&data[from..start]);
                        if self.buffer.len() > 0 {
                            let str = String::from_utf8(self.buffer.to_owned()).unwrap();
                            self.buffer.clear();
                            // If we have no method, we should parse the line as the start line
                            if let None = self.method {
                                self.parse_start_line(&str);
                            } else {
                                self.parse_header(&str);
                            }
                        } else {
                            // if we had a completely blank line, we should be done with headers
                            // and body, if any, should come after. we loop once more to reach
                            // first if arm, because we want to save the remaining of data into buffer
                            self.head_done = true;
                            // Break if the method is body-less
                            match self.method {
                                Some(HttpMethod::Get) => {
                                    self.done = true;
                                    break;
                                }
                                _ => ()
                            };
                        }
                        if end < length { // more remains in data buffer
                            from = end + 1;
                        } else {
                            break;
                        }
                    },
                    None => {
                        self.buffer.extend_from_slice(&data[from..length]);
                        break;
                    }
                }
            }
        }

        self.done
    }
    
    fn parse_start_line(&mut self, line: &str) {
        if let Some(idx) = line.find(' ') {
            match &line[0..idx] {
                "GET" => self.method = Some(HttpMethod::Get),
                other => (),
            };
            let rest_line = &line[idx+1..line.len()];
            let tag_idx = rest_line.rfind(" HTTP/");
            match tag_idx {
                Some(tag_idx) => {
                    self.target = Some(rest_line[0..tag_idx].to_owned());
                    let http_tag = &rest_line[tag_idx+6..];
                    match http_tag {
                        "1.1" => self.protocol_version = Some(HttpVersion::OnePointOne),
                        other => self.protocol_version = None
                    }
                },
                None => {
                    self.done = true;
                }
            }

            
        } else {
            self.done = true;
        }
    }

    fn parse_header(&mut self, line: &str) {
        if let Some(idx) = line.find(':') {
            let header_name = line[0..idx].to_lowercase();
            let header_value = line[idx+1..].trim();
            match &header_name[..] {
                "content-length" => {
                    if let Ok(v) = str::parse(&header_value) {
                        self.content_length = Some(v);
                    }
                },
                other => {
                    let h = HttpHeader { name: header_name, value: header_value.to_owned() };
                    self.headers.push(h);
                }
            }
        } else {
            // todo could not parse header
        }
    }

    fn get_body(&mut self) -> Option<String> {
        // todo not impl
        None
    }

}

fn find_newline_index(data: &[u8], from: usize, to: usize) -> Option<(usize, usize)> {
    // Input data is assumed to be either utf-8 or ascii.
    // Finds either CR (13) and/or LF (10) in data. 
    // Returns the start and end index of the new line.
    // If start==end, only one char was found (CR or LF).
    // End is always either start or start+1;
    let mut i = from;
    let mut res = None;
    while i < to {
        if data[i] == 13 || data[i] == 10 {
            let start = i;
            let mut end = i;
            if data[i] == 13 && i + 1 < to && data[i + 1] == 10 {
                end = i + 1;
            }
            res = Some((start, end));
            break;
        }
        i += 1;
    }
    res
}

#[derive(Debug)]
pub struct HttpRequest {
    pub method: Option<HttpMethod>,
    pub target: Option<String>,
    pub protocol_version: Option<HttpVersion>,
    pub content_length: Option<u64>,
    pub headers: Vec<HttpHeader>,
    body: Vec<u8>,
    done: bool,
}

impl HttpRequest {
    pub fn new() -> HttpRequest {
        HttpRequest {
            method: None,
            target: None,
            protocol_version: None,
            content_length: None,
            headers: vec![],
            body: vec![],
            done: false,
        }
    }

    pub fn parse_start_line(&mut self, line: &str) -> Result<(), HttpError> {
        if self.done {
            return Err(HttpError::InternalServerError);
        }
        let res = if let Some(idx) = line.find(" ") {
            match &line[0..idx] {
                "GET" => {
                    self.method = Some(HttpMethod::Get);
                    Ok(())
                },
                other => Err(HttpError::MethodNotSupported(other.to_owned())),
            }?;
            let rest_line = &line[idx+1..line.len()];
            let tag_idx = rest_line.rfind(" HTTP/");
            match tag_idx {
                Some(tag_idx) => {
                    // Must have length of at least one
                    match tag_idx {
                        0 => Err(HttpError::BadRequest),
                        _ => Ok(())
                    }?;
                    self.target = Some(rest_line[0..tag_idx].to_owned());
                    let http_tag = &rest_line[tag_idx+6..];
                    match http_tag {
                        "1.1" => { 
                            self.protocol_version = Some(HttpVersion::OnePointOne);
                            Ok(())
                        },
                        other => { 
                            Err(HttpError::VersionNotSupported(other.to_owned()))
                        }
                    }
                },
                None => {
                    Err(HttpError::BadRequest)
                }
            }
        } else {
            Err(HttpError::BadRequest)
        };
        self.done = match res { Ok(_) => false, Err(_) => true };
        res
    }
    
    pub fn parse_header(&mut self, line: &str) {
        if let Some(idx) = line.find(':') {
            let header_name = line[0..idx].to_lowercase();
            let header_value = line[idx+1..].trim();
            match &header_name[..] {
                "content-length" => {
                    if let Ok(v) = str::parse(&header_value) {
                        self.content_length = Some(v);
                    }
                },
                _ => {
                    let h = HttpHeader { name: header_name, value: header_value.to_owned() };
                    self.headers.push(h);
                }
            }
        } else {
            // todo could not parse header
        }
    }

    fn connection_keep_alive(self) -> bool {
        if let Some(h) = self.headers.iter().find(|x| x.name == "connection") {
            h.value.to_lowercase() == "keep-alive"
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn can_parse_get_request() {
        let inp = "GET /foobar HTTP/1.1\r\nContent-Length: 128\r\nMyOtherHeader: HejMor\r\n\r\nbody content here";
        let mut req = HttpRequestOld::new();
        let bytes = inp.as_bytes();
        req.read_stream(bytes, bytes.len());
        assert_eq!(Some(HttpMethod::Get), req.method);
        assert_eq!(Some(128), req.content_length);
        assert_eq!(Some("/foobar".to_owned()), req.target);
        assert_eq!(Some(HttpVersion::OnePointOne), req.protocol_version);
        assert_eq!(1, req.headers.len());
        assert_eq!("HejMor".to_owned(), req.headers[0].value);
        assert_eq!(None, req.get_body());
    }

    
    #[test_case(crate::test_data::HTTP_REQ_GET; "plain get")]
    #[test_case(crate::test_data::HTTP_REQ_GET_MINIMAL_WITH_PATH_FOO; "plain get with path")]
    #[test_case(crate::test_data::HTTP_REQ_GET_MINIMAL_WITH_URL; "get with full url")]
    fn parses_valid_start_lines(request: &str) {
        // parse_start_line assumes there's no newlines in the input
        let line = request.lines().into_iter().next().unwrap();
        let mut req = HttpRequest::new();
        assert_eq!(req.parse_start_line(line), Ok(()));
        assert_eq!(req.done, false);
    }
}
