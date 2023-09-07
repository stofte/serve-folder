# Serve HTTP

WIP developer utility for serving a directory via HTTP, similar to
nodes [http-server](https://www.npmjs.com/package/http-server).
Tested on Windows only for now.

- Improve logging
- Make error handling non-fatal
- Cross-platform handling
- Default document (index.htm, index.html, etc)
- Setting/configuring mime-types?
- HTTPS (?)

# Usage

	Basic utility for serving up a directory via HTTP

	Usage: servehttp.exe [OPTIONS] [WWWROOT]

	Arguments:
	  [WWWROOT]  Optional server base directory

	Options:
	  -p, --port <PORT>  Server port [default: 8888]
	  -b, --bind <BIND>  Network interface to bind [default: localhost]
	  -h, --help         Print help

Examples:

	> servehttp -p 80 C:\temp\
	Serving "C:\temp" @ localhost:80
