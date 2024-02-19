use crate::misc::{HttpError, HttpHeader, HttpMethod, HttpVersion};

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

    pub fn connection_keep_alive(self) -> bool {
        if let Some(h) = self.headers.iter().find(|x| x.name == "connection") {
            h.value.to_lowercase() == "keep-alive"
        } else {
            false
        }
    }

    pub fn target_ends_with_slash(&self) -> bool {
        if let Some(x) = &self.target {
            x.ends_with("/")
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

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
