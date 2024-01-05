# Serve Folder

WIP developer utility for serving a directory via HTTP(S), similar to
nodes [http-server](https://www.npmjs.com/package/http-server).

Tested on Windows only for now.

- Implicit filetypes
- Default document (index.htm, index.html, etc)
- Improve logging
- Cross-platform handling
- Configuring mime-types?
- Threading/pools?

## Usage

    Basic utility for serving up a directory via HTTP

    Usage: servehttp.exe [OPTIONS] [WWWROOT]

    Arguments:
      [WWWROOT]  Server base directory. Defaults to the current directory if not set

    Options:
      -p, --port <PORT>
              Server port [default: 8080]
      -b, --bind <BIND>
              Network interface to bind [default: localhost]
      -f, --certificate-filename <CERTIFICATE_FILENAME>
              Filepath for TLS certificate
      -w, --certificate-password <CERTIFICATE_PASSWORD>
              Optional password for the above TLS certificate
      -t, --certificate-thumbprint <CERTIFICATE_THUMBPRINT>
              Locally installed TLS certificate thumprint to use
      -h, --help
              Print help

## Examples:

	> servehttp -p 80 C:\temp\
	Serving "C:\temp" @ localhost:80

## Notes

- [OpenSSL certificate operations for "removing" password](https://serverfault.com/a/1106205/18877)
- [How to create PCSTR](https://github.com/microsoft/windows-rs/issues/2344) (only for `windows` crate)
- [GetLastError has issues with non-win32 errors](https://github.com/microsoft/windows-rs/issues/2639)
- [Reading Windows Terminal colors is not supported](https://github.com/microsoft/terminal/issues/3718)