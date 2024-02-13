#[derive(Debug, PartialEq)]
pub enum HttpMethod {
    Get
}

#[derive(Debug, PartialEq)]
pub enum HttpVersion {
    OnePointOne,
}

#[derive(Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, PartialEq)]
pub enum HttpError {
    BadRequest,
    InternalServerError,
    VersionNotSupported(String),
    MethodNotSupported(String),
    StreamError(StreamError)
}

#[derive(Debug, PartialEq)]
pub enum StreamError {
    /// Too much data was received to resolve the desired operation
    /// such as reading the next line or receiving a number of bytes.
    BufferOverflow,
    
    ConnectionClosed,
    ConnectionTimeout,
    ConnectionReset,
    /// Other connection error. String contains underlying error text.
    Other(String),
    /// Indicates we have previously detected another error with the stream
    /// and any future calls to a method requiring reading will fail.
    /// The real underlying state of any TCPStream is not actually knowable,
    /// as we are only aware of the Read trait of said stream.
    StreamNotConnected,
}
