#[cfg(test)]

// HTTP test requests. Note that rust always uses newlines in their strings, 
// regardless of the files actual line endings. To ensure "proper" CRLF line
// endings, we must manually add a \r before newlines.
pub const HTTP_REQ_GET: &str = "GET / HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_NON_EXISTENT_FILE: &str = "GET /some_file_not_here HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_README_MD: &str = "GET /readme.md HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_README_GLOB_TEST: &str = "GET /readme HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_CARGO_MULTIPLE_MATCH_GLOB_TEST: &str = "GET /Cargo HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_SRC_DIRECTORY_FOR_LISTING: &str = "GET /src HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_MINIMAL_WITH_PATH_FOO: &str = "GET /foo HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_MINIMAL_WITH_PATH_BAR: &str = "GET /bar HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_GET_MINIMAL_WITH_URL: &str = "GET http://localhost:8080/ HTTP/1.1\r\n\r\n";
pub const HTTP_REQ_POST: &str = "POST /foo HTTP/1.1\r
Connection: keep-alive\r
Content-Length: 11\r
\r
\"Hej mor\"\r
";
pub const HTTP_REQ_POST_MINIMAL_TRANSFER_ENCODING_CHUNKED: &str = "POST /foo HTTP/1.1\r
Transfer-Encoding: chunked\r
Connection: keep-alive\r
\r
e\r
Hej mor æøå\r
0\r
";
pub const HTTP_REQ_GET_CHROME_FULL: &str = "GET https://www.google.com/ HTTP/1.1\r
Host: www.google.com\r
Connection: keep-alive\r
sec-ch-ua: \"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"\r
sec-ch-ua-mobile: ?0\r
sec-ch-ua-platform: \"Windows\"\r
Upgrade-Insecure-Requests: 1\r
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r
Sec-Fetch-Site: none\r
Sec-Fetch-Mode: navigate\r
Sec-Fetch-User: ?1\r
Sec-Fetch-Dest: document\r
Accept-Encoding: gzip, deflate, br\r
Accept-Language: en-US,en;q=0.9\r
\r
";
// Following requests have various issues
pub const HTTP_ERR_GET_ONLY_ONE_NEWLINE: &str = "GET / HTTP/1.1\n";
