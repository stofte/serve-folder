use std::io::{BufReader, Read};
use crate::misc::{HttpError, StreamError};
use crate::request::HttpRequest;

pub struct StreamReader<'a> {
    buffer_max: usize,
    buffer: Vec<u8>,
    stream_buffer: Vec<u8>,
    stream: Box<dyn Read + 'a>,
    connected: bool,
}

impl<'a> StreamReader<'a> {
    pub fn new(stream: impl Read + 'a, buffer_max: usize) -> StreamReader<'a> {
        let mut v = Vec::new();
        v.resize(buffer_max, 0);
        StreamReader {
            buffer_max: buffer_max,
            buffer: vec![],
            stream_buffer: vec![0;buffer_max],
            connected: true,
            stream: Box::new(stream)
        }
    }

    /// Scans for newlines (linefeed) in the buffer.
    fn buffer_has_newline(&mut self, offset: usize) -> Option<usize> {
        let mut i = offset;
        while i < self.buffer.len() {
            if self.buffer[i] == 10 {
                break;
            }
            i += 1;
        }
        if i < self.buffer.len() {
            Some(i)
        } else {
            None
        }
    }

    /// Attempts to convert the contents of the buffer into an UTF-8 string.
    fn get_string_from_buffer(&mut self, newline: usize) -> String {
        let end = if newline > 0 && self.buffer[newline - 1] == 13 {
            newline - 1
        } else {
            newline
        };
        let str = String::from_utf8_lossy(&self.buffer[0..end]).into_owned();
        let left_over = &self.buffer[newline+1..self.buffer.len()];
        self.buffer = left_over.to_owned();
        str
    }

    /// Processes the result from reading the underlying stream. 
    /// If any error is encountered, we set the connected flag
    /// to false, indicating the stream is closed.
    fn process_read_result(&mut self, read_result: Result<usize, std::io::Error>) -> Option<StreamError> {
        match read_result {
            Ok(c) => {
                if c == 0 { // indicates the stream was closed "nicely"
                    self.connected = false;
                    Some(StreamError::ConnectionClosed)
                } else {
                    self.buffer.extend(&self.stream_buffer[0..c]);
                    if self.buffer.len() > self.buffer_max {
                        self.connected = false;
                        Some(StreamError::BufferOverflow)
                    } else {
                        None
                    }
                }
            },
            Err(e) => {
                self.connected = false;
                match e.kind() {
                    std::io::ErrorKind::TimedOut => {
                        Some(StreamError::ConnectionTimeout)
                    },
                    std::io::ErrorKind::ConnectionReset => {
                        Some(StreamError::ConnectionReset)
                    }
                    _ => {
                        Some(StreamError::Other(e.to_string()))
                    }
                }
            }
        }
    }

    /// Reads until the next newline is detected in the stream, 
    /// and returns the bytes read as an UTF-8 string.
    fn next_line(&mut self) -> Result<String, StreamError> {
        if !self.connected {
            return Err(StreamError::StreamNotConnected);
        }

        let mut index = 0;
        loop {
            let buf_has_nl = self.buffer_has_newline(index);
            if self.buffer.len() > 0 {
                // in case we had no nl, we don't want to rescan from the start
                index = self.buffer.len() - 1;
            }
            match buf_has_nl {
                Some(end) => {
                    // consume line
                    return Ok(self.get_string_from_buffer(end))
                },
                None => {
                    // no newlines found, read some more contents into the buffer
                    let read_c: Result<usize, std::io::Error> = self.stream.read(&mut self.stream_buffer);
                    let read_result = self.process_read_result(read_c);
                    match read_result {
                        None => {
                            // no err on read, just loop and see if we have any line yet
                            continue;
                        },
                        Some(e) => {
                            return Err(e)
                        }
                    }
                }
            }
        }
    }

    /// Attempts to read a fixed amount of bytes from the wrapped stream.
    fn next_bytes(&mut self, count: usize) -> Result<Vec<u8>, StreamError> {
        if !self.connected {
            return Err(StreamError::StreamNotConnected);
        }
        
        let mut buf = Vec::new();
        loop {
            if self.buffer.len() >= count {
                buf.extend(&self.buffer[0..count]);
                self.buffer.drain(0..count);
                break;
            } else {
                let read_c = self.stream.read(&mut self.stream_buffer);
                let read_result = self.process_read_result(read_c);
                match read_result {
                    None => (), // continue
                    Some(e) => {
                        return Err(e);
                    }
                }
            }
        }
        Ok(buf)
    }

    pub fn next_request(&mut self) -> Result<HttpRequest, HttpError> {
        let mut req = HttpRequest::new();

        // process start line
        match self.next_line() {
            Ok(r) => req.parse_start_line(&r),
            Err(e) => Err(HttpError::StreamError(e))
        }?;
        
        // all the headers
        loop {
            match self.next_line() {
                Ok(line) => {
                    // empty line indicates we've finished processing the header
                    if line.len() == 0 {
                        break;
                    } else {
                        req.parse_header(&line);
                    }
                },
                Err(e) => {
                    return Err(HttpError::StreamError(e));
                }
            }
        }

        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use crate::misc::{HttpMethod, HttpVersion};
    use crate::server::bind_server_socket;
    use crate::test_data::{HTTP_ERR_GET_ONLY_ONE_NEWLINE, HTTP_REQ_GET, HTTP_REQ_GET_CHROME_FULL, HTTP_REQ_GET_MINIMAL_WITH_PATH_BAR, HTTP_REQ_GET_MINIMAL_WITH_PATH_FOO, HTTP_REQ_POST};


    fn create_server_socket(timeout_ms: u64) -> (TcpListener, SocketAddr) {
        let server_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let server_socket = bind_server_socket(server_addr, timeout_ms).unwrap();
        let server_addr_real = server_socket.local_addr().unwrap().as_socket().unwrap(); 
        let listener: TcpListener = server_socket.into();
        return (listener, server_addr_real);
    }

    #[test]
    fn read_lines() {
        let mut r = StreamReader::new("hej mor\nmore lines\nxxx".as_bytes(), 1000);

        assert_eq!(r.next_line(), Ok("hej mor".to_owned()));
        assert_eq!(r.next_line(), Ok("more lines".to_owned()));
        // the "xxx" bytes are "lost", at least in when not using a real socket.
        assert_eq!(r.next_line(), Err(StreamError::ConnectionClosed));
    }

    #[test]
    fn mixed_newlines() {
        // we only handle optional CR, not other combos
        let mut r = StreamReader::new("1\r\n2\n3\r\n".as_bytes(), 1000);

        assert_eq!(r.next_line(), Ok("1".to_owned()));
        assert_eq!(r.next_line(), Ok("2".to_owned()));
        assert_eq!(r.next_line(), Ok("3".to_owned()));
    }

    #[test]
    fn connection_closed() {
        let (server, server_addr) = create_server_socket(4000);

        // server
        let server_handle = thread::spawn(move || {
            let connection = server.accept().unwrap();
            let mut r = StreamReader::new(connection.0, 1000);
            vec![
                r.next_line(), 
                r.next_line(),
                r.next_line(),
                r.next_line()
            ]
        });

        // client
        thread::spawn(move || {
            let mut stream = TcpStream::connect(server_addr).unwrap();
            stream.write("hej mor\n".as_bytes()).unwrap();
            stream.write("\n".as_bytes()).unwrap();
            stream.write("test hest\r\n".as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });

        // no real reason to wait for the client thread
        let server_result = server_handle.join().unwrap();

        assert_eq!(server_result[0], Ok("hej mor".to_owned()));
        assert_eq!(server_result[1], Ok("".to_owned()));
        assert_eq!(server_result[2], Ok("test hest".to_owned()));
        assert_eq!(server_result[3], Err(StreamError::ConnectionClosed));
    }

    #[test]
    fn next_bytes_after_lines() {
        let mut r = StreamReader::new("1\n2\n333\n444".as_bytes(), 1000);

        assert_eq!(r.next_line(), Ok("1".to_owned()));
        assert_eq!(r.next_line(), Ok("2".to_owned()));
        assert_eq!(r.next_bytes(7), Ok("333\n444".as_bytes().into()));
    }

    #[test]
    fn buffer_overflow() {
        let large_string = "0123456789".repeat(101);
        let mut r = StreamReader::new(large_string.as_bytes(), 100);

        assert_eq!(r.next_line(), Err(StreamError::BufferOverflow));
    }

    #[test]
    fn connection_timeout() {
        // we don't want to wait too long on timeout events, but 250 ms should 
        // be a reasonable value for operating system based on random ass guessing.
        let timeout_ms = 250;
        let (server, server_addr) = create_server_socket(timeout_ms);

        let server_handle = thread::spawn(move || {
            let connection = server.accept().unwrap();
            let mut r = StreamReader::new(connection.0, 1000);
            vec![
                r.next_line(), 
                r.next_line()
            ]
        });

        thread::spawn(move || {
            let mut stream = TcpStream::connect(server_addr).unwrap();
            stream.write("hej mor\n".as_bytes()).unwrap();
            thread::sleep(Duration::from_millis(timeout_ms * 2));
        });

        let server_result = server_handle.join().unwrap();

        assert_eq!(server_result[0], Ok("hej mor".to_owned()));
        assert_eq!(server_result[1], Err(StreamError::ConnectionTimeout));
    }

    #[test]
    fn saves_connection_state_on_error() {
        let mut r = StreamReader::new("1\r\n".as_bytes(), 1000);
        
        assert_eq!(r.next_line(), Ok("1".to_owned()));
        assert_eq!(r.next_line(), Err(StreamError::ConnectionClosed));
        assert_eq!(r.next_line(), Err(StreamError::StreamNotConnected));
        assert_eq!(r.next_bytes(10), Err(StreamError::StreamNotConnected));
    }



    #[test]
    fn simple_get_request() {
        let mut r = StreamReader::new(HTTP_REQ_GET.as_bytes(), 1000);
        let req = r.next_request().unwrap();
        assert_eq!(req.method, Some(HttpMethod::Get));
    }

    #[test]
    fn handles_stream_errors() {
        let (server, server_addr) = create_server_socket(100);

        let server_handle = thread::spawn(move || {
            let connection = server.accept().unwrap();
            let mut r = StreamReader::new(connection.0, 1000);
            vec![
                r.next_request()
            ]
        });

        thread::spawn(move || {
            let mut stream = TcpStream::connect(server_addr).unwrap();
            // A full valid request would end with two newlines
            stream.write(HTTP_ERR_GET_ONLY_ONE_NEWLINE.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let mut res = server_handle.join().unwrap();
        let req = res.pop().unwrap();
        assert!(req.is_err());
        assert_eq!(req.unwrap_err(), HttpError::StreamError(StreamError::ConnectionClosed));
    }

    #[test]
    fn multiple_requests_on_same_connection() {
        let (server, server_addr) = create_server_socket(100);

        let server_handle = thread::spawn(move || {
            let connection = server.accept().unwrap();
            let mut r = StreamReader::new(connection.0, 1000);
            vec![
                r.next_request(),
                r.next_request(),
            ]
        });

        thread::spawn(move || {
            let mut stream = TcpStream::connect(server_addr).unwrap();
            stream.write(HTTP_REQ_GET_MINIMAL_WITH_PATH_FOO.as_bytes()).unwrap();
            stream.write(HTTP_REQ_GET_MINIMAL_WITH_PATH_BAR.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let mut res = server_handle.join().unwrap();
        let req2 = res.pop().unwrap();
        let req1 = res.pop().unwrap();

        assert!(req1.is_ok());
        assert!(req2.is_ok());

        let req1 = req1.unwrap();
        let req2 = req2.unwrap();

        assert_eq!(req1.method.unwrap(), HttpMethod::Get);
        assert_eq!(req1.target.unwrap(), "/foo");
        assert_eq!(req1.protocol_version.unwrap(), HttpVersion::OnePointOne);
        assert_eq!(req2.target.unwrap(), "/bar");
        assert_eq!(req2.method.unwrap(), HttpMethod::Get);
        assert_eq!(req2.protocol_version.unwrap(), HttpVersion::OnePointOne);
    }

    #[test]
    fn can_parse_a_realistic_get_request() {
        let mut reader = StreamReader::new(HTTP_REQ_GET_CHROME_FULL.as_bytes(), 1000);
        let req = reader.next_request();

        assert!(req.is_ok());
        let req = req.unwrap();
        assert_eq!(req.method.unwrap(), HttpMethod::Get);
        assert_eq!(req.target.unwrap(), "https://www.google.com/");
        assert!(req.headers.iter().find(|x| x.name == "connection").is_some());
    }

    #[test]
    fn method_not_supported_is_returned() {
        let mut reader = StreamReader::new(HTTP_REQ_POST.as_bytes(), 1000);

        let req1 = reader.next_request();

        assert!(req1.is_err());
        assert_eq!(req1.unwrap_err(), HttpError::MethodNotSupported("POST".to_owned()));
    }
}
