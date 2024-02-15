use std::fs::File;
use std::io::{BufReader, Error, Read, Write};
use crate::misc::{HttpError, StreamError};
use crate::request::HttpRequest;

trait ReadWrite: std::io::Read + std::io::Write {}
impl<T: Read + Write> ReadWrite for T {} 

/// Wraps a readable/writeable stream of bytes, 
/// and provides some conviniece functions for it
pub struct Stream<'a> {
    buffer_max: usize,
    buffer: Vec<u8>,
    stream_buffer: Vec<u8>,
    stream: Box<dyn ReadWrite + 'a>,
    connected: bool,
}

impl<'a> Stream<'a> {
    pub fn new(stream: impl ReadWrite + 'a, buffer_max: usize) -> Stream<'a> {
        let mut v = Vec::new();
        v.resize(buffer_max, 0);
        Stream {
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
                Some(map_io_err(e))
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


    pub fn write_all(&mut self, data: &[u8]) -> Result<(), StreamError>{
        match self.stream.write_all(data) {
            Ok(()) => Ok(()),
            Err(e) => {
                Err(map_io_err(e))
            }
        }
    }

    pub fn write_reader(&mut self, br: &mut BufReader<File>) -> Result<u64, StreamError> {
        match std::io::copy(br, &mut self.stream) {
            Ok(n) => Ok(n),
            Err(e) => {
                Err(map_io_err(e))
            }
        }
    }
}

fn map_io_err(e: Error) -> StreamError {
    match e.kind() {
        std::io::ErrorKind::TimedOut => {
            StreamError::ConnectionTimeout
        },
        std::io::ErrorKind::ConnectionReset => {
            StreamError::ConnectionReset
        }
        _ => {
            StreamError::Other(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
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

    fn wrap_str(s: &str) -> VecDeque<u8> {
        VecDeque::from(s.as_bytes().to_owned())
    }

    #[test]
    fn read_lines() {
        let mut s = Stream::new(wrap_str("hej mor\nmore lines\nxxx"), 1000);

        assert_eq!(s.next_line(), Ok("hej mor".to_owned()));
        assert_eq!(s.next_line(), Ok("more lines".to_owned()));
        // the "xxx" bytes are "lost", at least in when not using a real socket.
        assert_eq!(s.next_line(), Err(StreamError::ConnectionClosed));
    }

    #[test]
    fn mixed_newlines() {
        // we only handle optional CR, not other combos
        let mut s = Stream::new(wrap_str("1\r\n2\n3\r\n"), 1000);

        assert_eq!(s.next_line(), Ok("1".to_owned()));
        assert_eq!(s.next_line(), Ok("2".to_owned()));
        assert_eq!(s.next_line(), Ok("3".to_owned()));
    }

    #[test]
    fn connection_closed() {
        let (listener, server_addr) = create_server_socket(4000);

        // server
        let server_handle = thread::spawn(move || {
            let connection = listener.accept().unwrap();
            let mut s = Stream::new(connection.0, 1000);
            vec![
                s.next_line(), 
                s.next_line(),
                s.next_line(),
                s.next_line()
            ]
        });

        // client
        thread::spawn(move || {
            let mut s = TcpStream::connect(server_addr).unwrap();
            s.write("hej mor\n".as_bytes()).unwrap();
            s.write("\n".as_bytes()).unwrap();
            s.write("test hest\r\n".as_bytes()).unwrap();
            s.shutdown(std::net::Shutdown::Both).unwrap();
        });

        // no real reason to wait for the client thread
        let result = server_handle.join().unwrap();

        assert_eq!(result[0], Ok("hej mor".to_owned()));
        assert_eq!(result[1], Ok("".to_owned()));
        assert_eq!(result[2], Ok("test hest".to_owned()));
        assert_eq!(result[3], Err(StreamError::ConnectionClosed));
    }

    #[test]
    fn next_bytes_after_lines() {
        let mut s = Stream::new(wrap_str("1\n2\n333\n444"), 1000);

        assert_eq!(s.next_line(), Ok("1".to_owned()));
        assert_eq!(s.next_line(), Ok("2".to_owned()));
        assert_eq!(s.next_bytes(7), Ok("333\n444".as_bytes().into()));
    }

    #[test]
    fn buffer_overflow() {
        let inp = VecDeque::from((b"0123456789".repeat(101)).to_owned());
        let mut s = Stream::new(inp, 100);

        assert_eq!(s.next_line(), Err(StreamError::BufferOverflow));
    }

    #[test]
    fn connection_timeout() {
        // we don't want to wait too long on timeout events, but 250 ms should 
        // be a reasonable value for operating system based on random ass guessing.
        let timeout_ms = 250;
        let (listener, server_addr) = create_server_socket(timeout_ms);

        let server_handle = thread::spawn(move || {
            let connection = listener.accept().unwrap();
            let mut s = Stream::new(connection.0, 1000);
            vec![
                s.next_line(), 
                s.next_line()
            ]
        });

        thread::spawn(move || {
            let mut s = TcpStream::connect(server_addr).unwrap();
            s.write("hej mor\n".as_bytes()).unwrap();
            thread::sleep(Duration::from_millis(timeout_ms * 2));
        });

        let server_result = server_handle.join().unwrap();

        assert_eq!(server_result[0], Ok("hej mor".to_owned()));
        assert_eq!(server_result[1], Err(StreamError::ConnectionTimeout));
    }

    #[test]
    fn saves_connection_state_on_error() {
        let mut s = Stream::new(wrap_str("1\r\n"), 1000);
        
        assert_eq!(s.next_line(), Ok("1".to_owned()));
        assert_eq!(s.next_line(), Err(StreamError::ConnectionClosed));
        assert_eq!(s.next_line(), Err(StreamError::StreamNotConnected));
        assert_eq!(s.next_bytes(10), Err(StreamError::StreamNotConnected));
    }

    #[test]
    fn simple_get_request() {
        let mut s = Stream::new(wrap_str(HTTP_REQ_GET), 1000);
        let request = s.next_request().unwrap();
        assert_eq!(request.method, Some(HttpMethod::Get));
    }

    #[test]
    fn handles_stream_errors() {
        let (listener, server_addr) = create_server_socket(100);

        let server_handle = thread::spawn(move || {
            let connection = listener.accept().unwrap();
            let mut s = Stream::new(connection.0, 1000);
            vec![
                s.next_request()
            ]
        });

        thread::spawn(move || {
            let mut stream = TcpStream::connect(server_addr).unwrap();
            // A full valid request would end with two newlines
            stream.write(HTTP_ERR_GET_ONLY_ONE_NEWLINE.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let mut result = server_handle.join().unwrap();
        let request = result.pop().unwrap();
        assert!(request.is_err());
        assert_eq!(request.unwrap_err(), HttpError::StreamError(StreamError::ConnectionClosed));
    }

    #[test]
    fn multiple_requests_on_same_connection() {
        let (listener, server_addr) = create_server_socket(100);

        let server_handle = thread::spawn(move || {
            let connection = listener.accept().unwrap();
            let mut s = Stream::new(connection.0, 1000);
            vec![
                s.next_request(),
                s.next_request(),
            ]
        });

        thread::spawn(move || {
            let mut stream = TcpStream::connect(server_addr).unwrap();
            stream.write(HTTP_REQ_GET_MINIMAL_WITH_PATH_FOO.as_bytes()).unwrap();
            stream.write(HTTP_REQ_GET_MINIMAL_WITH_PATH_BAR.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let mut result = server_handle.join().unwrap();
        let req2 = result.pop().unwrap();
        let req1 = result.pop().unwrap();

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
        let mut stream = Stream::new(wrap_str(HTTP_REQ_GET_CHROME_FULL), 1000);
        let req = stream.next_request();

        assert!(req.is_ok());
        let req = req.unwrap();
        assert_eq!(req.method.unwrap(), HttpMethod::Get);
        assert_eq!(req.target.unwrap(), "https://www.google.com/");
        assert!(req.headers.iter().find(|x| x.name == "connection").is_some());
    }

    #[test]
    fn method_not_supported_is_returned() {
        let mut stream = Stream::new(wrap_str(HTTP_REQ_POST), 1000);

        let req1 = stream.next_request();

        assert!(req1.is_err());
        assert_eq!(req1.unwrap_err(), HttpError::MethodNotSupported("POST".to_owned()));
    }

    #[test]
    fn can_write_to_tcpstream() {
        let (listener, server_addr) = create_server_socket(100);

        // in this case, the stream acts as "client"
        let read_handle = thread::spawn(move || {
            let incoming = listener.accept().unwrap();
            let mut sock = incoming.0;
            let mut read_buf = [0 as u8;100];
            let read_c = sock.read(&mut read_buf).unwrap();
            String::from_utf8_lossy(&read_buf[0..read_c]).into_owned()
        });

        let socket = TcpStream::connect(server_addr).unwrap();
        let mut stream = Stream::new(socket, 1000);
        let write_c = stream.write_all(b"hej mor");

        let read_str = read_handle.join().unwrap();

        assert_eq!(write_c, Ok(()));
        assert_eq!(read_str, "hej mor".to_owned());
    }

    #[test]
    fn can_write_bufreader_to_tcpstream() {
        let (listener, server_addr) = create_server_socket(1000);
        
        let read_handle = thread::spawn(move || {
            let incoming = listener.accept().unwrap();
            let mut sock = incoming.0;
            let mut read_buf = [0 as u8;10000];
            let read_c = sock.read(&mut read_buf).unwrap();
            String::from_utf8_lossy(&read_buf[0..read_c]).into_owned()
        });

        let file = File::open("readme.md").unwrap();
        let file_size = file.metadata().unwrap().len();
        let mut br = BufReader::new(file);
        let mut file_contents = String::new();
        File::open("readme.md").unwrap().read_to_string(&mut file_contents).unwrap();        
        
        let socket = TcpStream::connect(server_addr).unwrap();
        let mut stream = Stream::new(socket, 1000);
        
        let write_c = stream.write_reader(&mut br);

        let read_str = read_handle.join().unwrap();

        assert_eq!(write_c, Ok(file_size));
        assert_eq!(read_str, file_contents);
    }
}
